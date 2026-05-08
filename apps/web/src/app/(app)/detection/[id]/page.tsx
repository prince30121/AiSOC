import { RuleEditor } from '@/components/detections/RuleEditor';

interface DetectionEditPageProps {
  params: Promise<{ id: string }>;
}

export const metadata = {
  title: 'Detection rule | AiSOC',
};

export default async function DetectionEditPage({
  params,
}: DetectionEditPageProps) {
  const { id } = await params;
  return <RuleEditor mode="edit" ruleId={id} />;
}
