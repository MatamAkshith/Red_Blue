import React from "react";

export type BadgeVariant =
  | "critical"
  | "malicious"
  | "warning"
  | "suspicious"
  | "success"
  | "benign"
  | "info"
  | "neutral"
  | "outline-critical";

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  className?: string;
  size?: "sm" | "md";
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = "neutral",
  className = "",
  size = "md",
}) => {
  const baseStyle =
    "inline-flex items-center font-mono font-semibold uppercase tracking-wider rounded-xs border transition-colors";

  const sizeStyles = {
    sm: "text-[10px] px-1.5 py-0.5 leading-none",
    md: "text-xs px-2 py-0.5 leading-tight",
  };

  const variantStyles: Record<BadgeVariant, string> = {
    critical: "bg-red-600 text-white border-red-700 font-extrabold shadow-2xs",
    malicious: "bg-rose-600 text-white border-rose-700 font-bold shadow-2xs",
    warning: "bg-amber-500 text-slate-950 border-amber-600 font-bold shadow-2xs",
    suspicious: "bg-amber-500 text-slate-950 border-amber-600 font-bold shadow-2xs",
    success: "bg-emerald-600 text-white border-emerald-700 font-bold shadow-2xs",
    benign: "bg-emerald-600 text-white border-emerald-700 font-bold shadow-2xs",
    info: "bg-blue-600 text-white border-blue-700 font-bold shadow-2xs",
    neutral: "bg-slate-100 text-slate-700 border-slate-300 font-semibold shadow-2xs",
    "outline-critical": "bg-red-50 text-red-700 border-2 border-red-600 font-extrabold",
  };

  return (
    <span
      className={`${baseStyle} ${sizeStyles[size]} ${variantStyles[variant]} ${className}`}
    >
      {children}
    </span>
  );
};
