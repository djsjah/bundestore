import { Slider } from './Slider';

type LabeledSliderProps = {
  defaultValue?: number[];
  value: number[];
  onValueChange: (value: number[]) => void;
  max: number;
  step?: number;
  formatLabel?: (value: number) => string;
};

export const LabeledSlider: React.FC<LabeledSliderProps> = ({
  defaultValue,
  value,
  onValueChange,
  max,
  step = 1,
  formatLabel = (value: number) => value,
}) => {
  return (
    <div className="space-y-2">
      <Slider defaultValue={defaultValue} max={max} step={step} value={value} onValueChange={onValueChange} />
      <div className="text-center font-medium">{formatLabel(value[0])}</div>
    </div>
  );
};
