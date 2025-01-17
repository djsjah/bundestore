import { Label } from '@radix-ui/react-label';

import { formatDate } from '@/utils';

import { Card, CardContent, Input } from '../shadcn';

type UserInfoProps = {
  firstName: string;
  lastName: string;
  email: string;
  phoneNumber: string;
  birthDate: string;
};

export const UserInfo: React.FC<UserInfoProps> = ({ firstName, lastName, email, phoneNumber, birthDate }) => {
  return (
    <Card className="w-full max-w-lg mx-auto p-6">
      <CardContent className="flex flex-col gap-4 p-0">
        <div className="flex flex-col gap-4 pb-6 border-b-2 border-b-zinc-900">
          <h4 className="font-semibold">Main Information</h4>
          <div className="flex flex-col gap-4 lg:flex-row">
            <div className="flex-1 flex flex-col gap-2">
              <Label>First Name:</Label>
              <Input value={firstName} disabled readOnly className="!opacity-100 !cursor-text" />
            </div>
            <div className="flex-1 flex flex-col gap-2">
              <Label>Last Name:</Label>
              <Input value={lastName} disabled readOnly className="!opacity-100 !cursor-text" />
            </div>
          </div>
          <div className="flex flex-col gap-2">
            <Label>Birth Date:</Label>
            <Input value={formatDate(new Date(birthDate))} disabled readOnly className="!opacity-100 !cursor-text" />
          </div>
        </div>
        <div className="flex flex-col gap-4">
          <h4 className="font-semibold">Contact Information</h4>
          <div className="flex flex-col gap-4 lg:flex-row">
            <div className="flex-1 flex flex-col gap-2">
              <Label>Email:</Label>
              <Input value={email} disabled readOnly className="!opacity-100 !cursor-text" />
            </div>
            <div className="flex-1 flex flex-col gap-2">
              <Label>Phone Number:</Label>
              <Input value={phoneNumber} disabled readOnly className="!opacity-100 !cursor-text" />
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
