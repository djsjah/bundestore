/* eslint-disable max-len */
import { SIZE_LABELS } from '@/constants';
import type { GetClothingSizeDTO, GetFootwearSizeDTO } from '@/api';
import { cn } from '@/utils';

type SizeOptionProps = {
  size: GetClothingSizeDTO | GetFootwearSizeDTO;
  isSelected?: boolean;
  onSelect?: (size: string) => void;
  disabled?: boolean;
};

export const SizeOption: React.FC<SizeOptionProps> = ({ size, isSelected, onSelect, disabled = false }) => {
  return (
    <div
      onClick={() => {
        if (onSelect) {
          onSelect(size);
        }
      }}
      className={cn(
        'bg-transparent h-10 min-w-10 flex items-center justify-center border-2 border-zinc-900 rounded-md cursor-pointer p-2 text-xs transition-colors duration-200 hover:border-zinc-800',
        { 'bg-zinc-800': isSelected, 'pointer-events-none opacity-60': disabled },
      )}
    >
      {SIZE_LABELS[size]}
    </div>
  );
};
