import React, { useState, forwardRef } from 'react';

import VisibilityOnIcon from '@/assets/icons/visibility-on.svg?react';
import VisibilityOffIcon from '@/assets/icons/visibility-off.svg?react';

import { Button, Input } from '../shadcn';

type PasswordInputProps = React.InputHTMLAttributes<HTMLInputElement>;

export const PasswordInput: React.FC<PasswordInputProps> = forwardRef<HTMLInputElement, PasswordInputProps>(
  (inputProps, ref) => {
    const [showPassword, setShowPassword] = useState(false);

    return (
      <div className="relative">
        <Input type={showPassword ? 'text' : 'password'} {...inputProps} ref={ref} className="pr-10" />
        <Button
          type="button"
          variant="ghost"
          onClick={() => setShowPassword(!showPassword)}
          className="absolute top-1/2 right-0 transform -translate-y-1/2"
        >
          {showPassword ? <VisibilityOnIcon /> : <VisibilityOffIcon />}
        </Button>
      </div>
    );
  },
);

PasswordInput.displayName = 'PasswordInput';
