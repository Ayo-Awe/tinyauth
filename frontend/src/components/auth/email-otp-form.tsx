import { useTranslation } from "react-i18next";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import axios, { AxiosError } from "axios";
import { useRef, useState } from "react";
import { toast } from "sonner";
import z from "zod";
import { Input } from "../ui/input";
import { Button } from "../ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "../ui/form";
import {
  emailOtpCodeSchema,
  EmailOtpCodeSchema,
  emailOtpSendSchema,
  EmailOtpSendSchema,
} from "@/schemas/email-otp-schema";

interface Props {
  onSuccess: () => void;
  disabled?: boolean;
}

export const EmailOtpForm = (props: Props) => {
  const { onSuccess, disabled } = props;
  const { t } = useTranslation();
  const [email, setEmail] = useState<string | null>(null);
  const autoSubmittedRef = useRef(false);

  z.config({
    customError: (iss) =>
      iss.input === undefined ? t("fieldRequired") : t("invalidInput"),
  });

  const requestForm = useForm<EmailOtpSendSchema>({
    resolver: zodResolver(emailOtpSendSchema),
  });

  const codeForm = useForm<EmailOtpCodeSchema>({
    resolver: zodResolver(emailOtpCodeSchema),
  });

  const { mutate: requestCode, isPending: requestIsPending } = useMutation({
    mutationFn: (values: EmailOtpSendSchema) =>
      axios.post("/api/user/email-otp/send", values),
    mutationKey: ["email-otp-send"],
    onSuccess: (_, values) => {
      setEmail(values.email);
      codeForm.reset({ code: "" });
      toast.info(t("loginEmailOtpSentTitle"), {
        description: t("loginEmailOtpSentSubtitle"),
      });
    },
    onError: (error: AxiosError) => {
      toast.error(t("loginFailTitle"), {
        description:
          error.response?.status === 429
            ? t("loginEmailOtpRateLimit")
            : t("loginEmailOtpSendFail"),
      });
    },
  });

  const { mutate: verifyCode, isPending: verifyIsPending } = useMutation({
    mutationFn: (values: EmailOtpCodeSchema) =>
      axios.post("/api/user/email-otp/verify", { email, code: values.code }),
    mutationKey: ["email-otp-verify"],
    onSuccess: () => onSuccess(),
    onError: (error: AxiosError) => {
      autoSubmittedRef.current = false;
      toast.error(t("loginFailTitle"), {
        description:
          error.response?.status === 429
            ? t("loginFailRateLimit")
            : t("loginEmailOtpVerifyFail"),
      });
    },
  });

  const loading = disabled || requestIsPending || verifyIsPending;

  if (email === null) {
    return (
      <Form {...requestForm}>
        <form
          className="flex flex-col gap-3"
          onSubmit={requestForm.handleSubmit((values) => requestCode(values))}
        >
          <FormField
            control={requestForm.control}
            name="email"
            render={({ field }) => (
              <FormItem className="gap-0">
                <FormLabel className="mb-2">{t("loginEmail")}</FormLabel>
                <FormControl className="mb-1">
                  <Input
                    type="email"
                    placeholder="you@example.com"
                    autoComplete="email"
                    disabled={loading}
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <Button type="submit" className="w-full" loading={requestIsPending}>
            {t("loginEmailOtpSend")}
          </Button>
        </form>
      </Form>
    );
  }

  const handleCodeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/\D/g, "").slice(0, 6);
    codeForm.setValue("code", value, {
      shouldDirty: true,
      shouldValidate: false,
    });
    if (value.length === 6 && !autoSubmittedRef.current) {
      autoSubmittedRef.current = true;
      codeForm.handleSubmit((values) => verifyCode(values))();
    }
  };

  return (
    <Form {...codeForm}>
      <form
        className="flex flex-col gap-3"
        onSubmit={codeForm.handleSubmit((values) => verifyCode(values))}
      >
        <FormField
          control={codeForm.control}
          name="code"
          render={({ field }) => (
            <FormItem className="gap-0">
              <FormLabel className="mb-2">{t("loginEmailOtpCode")}</FormLabel>
              <FormControl className="mb-1">
                <Input
                  {...field}
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  autoFocus
                  maxLength={6}
                  placeholder="XXXXXX"
                  disabled={loading}
                  onChange={handleCodeChange}
                  className="text-center"
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button type="submit" className="w-full" loading={verifyIsPending}>
          {t("loginEmailOtpVerify")}
        </Button>
        <Button
          type="button"
          variant="outline"
          className="w-full"
          disabled={loading}
          onClick={() => setEmail(null)}
        >
          {t("loginEmailOtpChangeEmail")}
        </Button>
      </form>
    </Form>
  );
};
