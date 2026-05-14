import { ShiftsView } from '@/components/shifts/ShiftsView';

export const metadata = { title: 'Shifts — AiSOC' };

export default function ShiftsPage() {
  return (
    <div className="p-6 max-w-7xl mx-auto">
      <ShiftsView />
    </div>
  );
}
