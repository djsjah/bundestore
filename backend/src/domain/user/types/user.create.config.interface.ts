export interface IUserCreateConfig {
  phoneNummber: {
    rule: RegExp;
    message: string;
  };
}
