import React from "react";

export type ButtonVariant = "primary" | "outline" | "ghost" | "danger";
export type ButtonSize = "sm" | "md" | "lg";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = "primary",
  size = "md",
  icon,
  className = "",
  disabled,
  ...props
}) => {
  const baseStyle =
    "inline-flex items-center justify-center font-medium rounded-sm transition-colors focus:outline-hidden disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer";

  const sizeStyles: Record<ButtonSize, string> = {
    sm: "text-xs px-2.5 py-1 space-x-1.5",
    md: "text-xs px-3 py-1.5 space-x-2",
    lg: "text-sm px-4 py-2 space-x-2",
  };

  const variantStyles: Record<ButtonVariant, string> = {
    primary:
      "bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white shadow-2xs border border-blue-700",
    outline:
      "bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 shadow-2xs active:bg-slate-100",
    ghost: "bg-transparent hover:bg-slate-100 text-slate-700 active:bg-slate-200",
    danger:
      "bg-red-600 hover:bg-red-700 active:bg-red-800 text-white shadow-2xs border border-red-700",
  };

  return (
    <button
      className={`${baseStyle} ${sizeStyles[size]} ${variantStyles[variant]} ${className}`}
      disabled={disabled}
      {...props}
    >
      {icon && <span className="shrink-0">{icon}</span>}
      <span>{children}</span>
    </button>
  );
};
