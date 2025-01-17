import { useCallback, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { APP_ROUTER } from '@/constants';
import { useAlert, useGetUserPayloadQuery, useSignOutMutation } from '@/hooks';
import { cn } from '@/utils';
import EditIcon from '@/assets/icons/edit.svg?react';

import {
  Avatar,
  AvatarFallback,
  AvatarImage,
  Button,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Skeleton,
} from '../shadcn';
import { ErrorMessage } from '../common';

export const QuickAccessDropdown: React.FC = () => {
  const navigate = useNavigate();

  const { openAlert } = useAlert();

  const [isOpen, setIsOpen] = useState(false);

  const { data: userData, isLoading: isLoadingUserData, isError: isErrorUserData } = useGetUserPayloadQuery();
  const { mutateAsync: signOutMutation, isPending: isSigningOut } = useSignOutMutation();

  const handleSignOut = useCallback(async () => {
    try {
      await signOutMutation();
      setIsOpen(false);
    } catch (e) {
      console.error('Error signing out: ', e);
      openAlert('Something went wrong!', 'destructive');
    }
  }, [signOutMutation, openAlert]);

  return (
    <Popover open={isOpen} onOpenChange={setIsOpen}>
      <PopoverTrigger>
        <Avatar className="cursor-pointer">
          <AvatarImage src="https://github.com/shadcn.png" />
          <AvatarFallback>A</AvatarFallback>
        </Avatar>
      </PopoverTrigger>
      <PopoverContent
        align="end"
        className={cn('w-72 p-4 backdrop-blur-sm border border-zinc-900 text-zinc-100 rounded-lg shadow-md', {
          'pointer-events-none opacity-80': isSigningOut,
        })}
      >
        {isLoadingUserData ? (
          <div className="flex flex-col gap-4">
            <Skeleton className="h-8" />
            <Skeleton className="h-6" />
          </div>
        ) : isErrorUserData ? (
          <ErrorMessage>Server Error</ErrorMessage>
        ) : (
          <div className="flex flex-col gap-6">
            <div>
              <div className="flex gap-4 justify-between items-center">
                <p className="text-lg font-semibold mb-2">
                  {userData?.firstName} {userData?.lastName}
                </p>
                <Button
                  type="button"
                  variant="ghost"
                  className="py-1 px-2"
                  onClick={() => {
                    navigate(APP_ROUTER.PROFILE);
                    setIsOpen(false);
                  }}
                >
                  <EditIcon />
                </Button>
              </div>
              <div className="flex flex-col">
                <p className="text-sm text-zinc-500">{userData?.email}</p>
                <p className="text-sm text-zinc-500">{userData?.phoneNumber}</p>
              </div>
            </div>
            <div className="flex flex-col gap-2">
              <Button
                type="button"
                variant="secondary"
                className="w-full"
                onClick={() => {
                  navigate(APP_ROUTER.ORDERS);
                  setIsOpen(false);
                }}
              >
                My Orders
              </Button>
              <Button
                type="button"
                variant="ghost"
                className="w-full"
                onClick={() => {
                  handleSignOut();
                  setIsOpen(false);
                }}
              >
                Logout
              </Button>
            </div>
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
};
