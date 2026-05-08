import { PlaybookEditor } from '@/components/playbooks/PlaybookEditor';

export const metadata = {
  title: 'Playbook Editor | AiSOC',
};

export default async function PlaybookEditorPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return (
    <div className="h-full">
      <PlaybookEditor playbookId={id} />
    </div>
  );
}
