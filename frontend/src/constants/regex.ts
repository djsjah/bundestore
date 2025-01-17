export const NAME_REGEX = /^[A-Za-zА-Яа-яЁё]+(?:[-\s][A-Za-zА-Яа-яЁё]+)*$/;

export const PASSWORD_REGEX = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*#?&])/;

export const DATE_REGEX = /^\d{2}\/\d{2}\/\d{4}$/;

export const PHONE_NUMBER_REGEX = /^\+1\s\([0-9]{3}\)\s[0-9]{3}-[0-9]{4}$/;
