export type SignUpDTO = {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  phoneNumber: string;
  birthDate: string;
};

export type SignInDTO = {
  email: string;
  password: string;
};

export type EmailVerificationDTO = {
  token: string;
};

export type GetUserPayloadDTO = {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  phoneNumber: string;
  birthDate: string;
};
