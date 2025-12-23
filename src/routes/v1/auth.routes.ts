import {
  changePassword,
  deleteAccount,
  getGoogleAuthConsentScreen,
  getUserProfile,
  googleAuthCallbackHandler,
  googleSignin,
  logout,
  reactivateAccount,
  refreshToken,
  resetPassword,
  signinUser,
  signupUser,
  updateProfile,
} from "#controllers/auth.controller.js";
import { sendOtp, verifyOtp } from "#controllers/otp.controller.js";
import {
  changePasswordLimiter,
  deleteAccountLimiter,
  otpRequestLimiter,
  otpVerificationLimiter,
  resetPasswordLimiter,
  signinLimiter,
  signupLimiter,
} from "#lib/rate-limiter.js";
import { checkEmailRestriction } from "#middlewares/check-email-restriction.js";
import upload from "#middlewares/upload-file.js";
import { isAuthenticated } from "#middlewares/verify-authentication.js";
import { Router } from "express";

const router = Router();

router.get("/profile", isAuthenticated, getUserProfile);

router.post("/signup", signupLimiter, signupUser);
router.post("/signin", signinLimiter, checkEmailRestriction, signinUser);

router.post("/request-otp", otpRequestLimiter, sendOtp);
router.post("/verify-otp", otpVerificationLimiter, verifyOtp);

router.post("/reset-password", resetPasswordLimiter, resetPassword);
router.post(
  "/change-password",
  isAuthenticated,
  checkEmailRestriction,
  changePasswordLimiter,
  changePassword
);

router.patch(
  "/update-profile",
  upload.single("avatar"),
  isAuthenticated,
  checkEmailRestriction,
  updateProfile
);

router.post("/google-signin", googleSignin);
router.get("/google", getGoogleAuthConsentScreen);
router.get("/google/callback", googleAuthCallbackHandler);

router.post("/refresh-token", refreshToken);
router.post("/logout", isAuthenticated, checkEmailRestriction, logout);

router.delete(
  "/delete-account",
  isAuthenticated,
  checkEmailRestriction,
  deleteAccountLimiter,
  deleteAccount
);
router.put("/reactivate-account", isAuthenticated, reactivateAccount);

export default router;
