import { ApiResponse } from "#utils/api-response.js";
import { NextFunction, Request, Response } from "express";

import { AsyncHandler } from "#utils/async-handler.js";
import { RequestOtpSchema, VerifyOtpSchema } from "#validators/auth.js";
import z from "zod";
import crypto from "crypto";
import { User } from "#models/user.model.js";
import {
  NEXT_OTP_DELAY,
  OTP_CODE_EXPIRY,
  OTP_CODE_LENGTH,
  OTP_MAX_ATTEMPTS,
  RESET_PASSWORD_TOKEN_EXPIRY,
} from "#constants/auth-constants.js";
import { generateOtp, generateRandomToken } from "#helpers/auth-helper.js";
import { logger } from "#utils/logger.js";
import Otp from "#models/otp.model.js";
import {
  generateAccessToken,
  generateRefreshToken,
} from "#helpers/jwt-helper.js";
import { AuthenticatedRequest } from "../types/user";
import { COOKIE_OPTIONS, setAuthCookies } from "#helpers/cookie-helper.js";
import { sendEmail } from "#lib/node-mailer.js";

//? SEND OTP
export const sendOtp = AsyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { success, data, error } = RequestOtpSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received",
        z.flattenError(error).fieldErrors,
      );
    }

    const { email, otpType } = data;
    if (!email || !otpType) {
      return ApiResponse.BadRequest(res, "Email and otpType are required");
    }

    const user = await User.findOne({ email });
    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60),
        )} minutes.`,
      );
    }

    const otp = generateOtp(OTP_CODE_LENGTH, OTP_CODE_EXPIRY);
    logger.info(`Generated OTP:  ${otp.code}`);

    const existingOtp = await Otp.findOne({ email });
    if (existingOtp && new Date(existingOtp.nextResendAllowedAt) > new Date()) {
      const remainingSec = Math.ceil(
        (existingOtp.nextResendAllowedAt.getTime() - Date.now()) / 1000,
      );
      return ApiResponse.BadRequest(
        res,
        `Please wait for ${remainingSec} seconds before sending another OTP`,
      );
    }

    const nextResendAllowedAt = new Date(Date.now() + NEXT_OTP_DELAY);

    const newOtp = new Otp({
      email,
      otpType,
      otpHashCode: otp.hashCode,
      attempts: 0,
      isVerified: false,
      expiresAt: otp.expiresAt,
      nextResendAllowedAt,
    });
    await newOtp.save();

    if (!newOtp) {
      return ApiResponse.BadRequest(res, "Failed to send OTP");
    }

    if (existingOtp) {
      existingOtp.nextResendAllowedAt = nextResendAllowedAt;
      await existingOtp.save();
    }
    if (otpType === "email-verification") {
      const html = `<p>OTP: ${otp.code}</p>`;
      // await sendEmail(email, `OTP for email verification`, html);
    }
    if (otpType === "password-reset") {
      const html = `<p>OTP: ${otp.code}</p>`;
      // await sendEmail(email, `OTP for password reset`, html);
    }

    return ApiResponse.Success(res, "OTP sent successfully");
  },
);

//? VERIFY OTP
export const verifyOtp = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const { success, data, error } = VerifyOtpSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received",
        z.flattenError(error).fieldErrors,
      );
    }

    const { email, otpCode } = data;
    if (!email || !otpCode) {
      return ApiResponse.BadRequest(res, "Email and otpCode are required");
    }

    const user = await User.findOne({ email });
    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60),
        )} minutes.`,
      );
    }

    const existingOtp = await Otp.findOne({
      email,
      isVerified: false,
      expiresAt: { $gt: new Date() },
    });
    if (!existingOtp) {
      return ApiResponse.NotFound(res, "Invalid or expired OTP");
    }

    if (existingOtp.attempts >= OTP_MAX_ATTEMPTS) {
      return ApiResponse.BadRequest(res, "Maximum attempts reached. Try later");
    }
    if (existingOtp.isVerified) {
      return ApiResponse.BadRequest(res, "OTP already verified");
    }

    if (new Date(existingOtp.expiresAt) < new Date()) {
      return ApiResponse.BadRequest(res, "OTP expired");
    }

    const otpHashCode = crypto
      .createHash("sha256")
      .update(String(otpCode))
      .digest("hex");
    if (existingOtp.otpHashCode !== otpHashCode) {
      await Otp.updateOne({ _id: existingOtp._id }, { $inc: { attempts: 1 } });
      return ApiResponse.BadRequest(res, "Invalid OTP code");
    }

    existingOtp.isVerified = true;
    await existingOtp.save();

    await Otp.deleteMany({ expiresAt: { $lt: new Date() } });

    if (existingOtp.otpType === "email-verification") {
      if (!user.isEmailVerified) {
        user.isEmailVerified = true;
        await user.save();
      }

      const payload = {
        _id: user._id.toString(),
      };
      const accessToken = generateAccessToken(payload);
      const refreshToken = generateRefreshToken(user._id.toString());
      setAuthCookies(res, accessToken, refreshToken);

      await User.updateOne(
        { _id: user._id },
        { $set: { lastLogin: new Date(), failedLoginAttempts: 0 } },
      );

      await User.updateOne({ _id: user._id }, { $unset: { lockUntil: 1 } });

      return ApiResponse.Success(
        res,
        "OTP verified and user logged in successfully",
      );
    }

    if (existingOtp.otpType === "password-reset") {
      const { hashedToken: hashedResetPasswordToken } = generateRandomToken(
        user._id.toString(),
      );
      const resetPasswordExpiry = new Date(
        Date.now() + RESET_PASSWORD_TOKEN_EXPIRY,
      );

      if (
        req.cookies?.hashedResetPasswordToken ||
        req.cookies?.resetPasswordExpiry
      ) {
        res.clearCookie("hashedResetPasswordToken");
        res.clearCookie("resetPasswordExpiry");
      }

      res.cookie(
        "hashedResetPasswordToken",
        hashedResetPasswordToken,
        COOKIE_OPTIONS,
      );
      res.cookie(
        "resetPasswordExpiry",
        resetPasswordExpiry.toISOString(),
        COOKIE_OPTIONS,
      );

      return ApiResponse.Success(res, "OTP verified successfully");
    }

    return ApiResponse.Success(res, "OTP verified successfully");
  },
);
