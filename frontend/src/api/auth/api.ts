import type { SignInDTO, SignUpDTO, EmailVerificationDTO, GetUserPayloadDTO } from './dto';

export const getUserPayload = async (): Promise<GetUserPayloadDTO> => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/auth/user-payload`, { credentials: 'include' });

  if (!response.ok) {
    const message = await response.text();
    throw {
      message,
      status: response.status,
    };
  }

  return await response.json();
};

export const signUp = async (userData: SignUpDTO) => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/auth/sign-up`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(userData),
  });

  if (!response.ok) {
    const message = await response.text();
    throw {
      message,
      status: response.status,
    };
  }
};

export const signIn = async (userData: SignInDTO) => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/auth/sign-in`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(userData),
    credentials: 'include',
  });

  if (!response.ok) {
    const message = await response.text();
    throw {
      message,
      status: response.status,
    };
  }
};

export const signOut = async () => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/auth/sign-out`, { credentials: 'include' });

  if (!response.ok) {
    const message = await response.text();
    throw {
      message,
      status: response.status,
    };
  }
};

export const verifyEmail = async (data: EmailVerificationDTO) => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/auth/verify-email`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
    credentials: 'include',
  });

  if (!response.ok) {
    const message = await response.text();
    throw {
      message,
      status: response.status,
    };
  }
};

export const resendVerificationEmail = async (email: string) => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/auth/resend-email/${email}`);

  if (!response.ok) {
    const message = await response.text();
    throw {
      message,
      status: response.status,
    };
  }

  return await response.text();
};

export const recoverPassword = async (email: string) => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/auth/recover-password/${email}`, {
    credentials: 'include',
  });

  if (!response.ok) {
    const message = await response.text();
    throw {
      message,
      status: response.status,
    };
  }

  return await response.text();
};
