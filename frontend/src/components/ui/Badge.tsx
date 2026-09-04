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
    critical: "bg-red-50 text-red-700 border-red-200/80 shadow-2xs",
    malicious: "bg-red-50 text-red-700 border-red-300 shadow-2xs",
    warning: "bg-amber-50 text-amber-800 border-amber-300 shadow-2xs",
    suspicious: "bg-amber-50 text-amber-800 border-amber-300 shadow-2xs",
    success: "bg-emerald-50 text-emerald-700 border-emerald-300 shadow-2xs",
    benign: "bg-emerald-50 text-emerald-700 border-emerald-300 shadow-2xs",
    info: "bg-blue-50 text-blue-700 border-blue-200 shadow-2xs",
    neutral: "bg-slate-100 text-slate-700 border-slate-200 shadow-2xs",
    "outline-critical": "bg-transparent text-red-700 border-red-500/80 font-bold",
  };

  return (
    <span
      className={`${baseStyle} ${sizeStyles[size]} ${variantStyles[variant]} ${className}`}
    >
      {children}
    </span>
  );
};
