import { z } from "zod";

export const emailOtpSendSchema = z.object({
  email: z.email(),
});

export type EmailOtpSendSchema = z.infer<typeof emailOtpSendSchema>;

export const emailOtpCodeSchema = z.object({
  code: z.string().regex(/^\d{6}$/),
});

export type EmailOtpCodeSchema = z.infer<typeof emailOtpCodeSchema>;
