import { format } from 'date-fns';

export const formatDate = (date: Date, dateFormat: string = 'MM/dd/yyyy') => {
  return format(date, dateFormat);
};
