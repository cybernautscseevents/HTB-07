import React, { useState } from 'react';
import { askAiAboutScan, generateAiSummary } from '../../services/api';

function renderInline(text) {
  return text.split(/(\*\*[^*]+\*\*|__[^_]+__|`[^`]+`|\*[^*]+\*)/g).map((part, index) => {
    if ((part.startsWith('**') && part.endsWith('**')) || (part.startsWith('__') && part.endsWith('__'))) {
      return <strong key={index} className="font-semibold text-slate-100">{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={index} className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-xs text-blue-200">{part.slice(1, -1)}</code>;
    }
    if (part.startsWith('*') && part.endsWith('*')) {
      return <em key={index}>{part.slice(1, -1)}</em>;
    }
    return part;
  });
}

function MarkdownContent({ content }) {
  const lines = content.replace(/\r\n?/g, '\n').split('\n');
  const blocks = [];
  let paragraph = [];
  let listItems = [];
  let listType = '';

  const flushParagraph = () => {
    if (paragraph.length) {
      blocks.push({ type: 'paragraph', text: paragraph.join(' ') });
      paragraph = [];
    }
  };
  const flushList = () => {
    if (listItems.length) {
      blocks.push({ type: listType, items: listItems });
      listItems = [];
      listType = '';
    }
  };

  lines.forEach((line) => {
    const trimmed = line.trim();
    const heading = trimmed.match(/^#{1,3}\s+(.+)$/);
    const unorderedItem = trimmed.match(/^[-*]\s+(.+)$/);
    const orderedItem = trimmed.match(/^\d+[.)]\s+(.+)$/);

    if (!trimmed || /^[-*_]{3,}$/.test(trimmed)) {
      flushParagraph();
      flushList();
      return;
    }
    if (heading) {
      flushParagraph();
      flushList();
      blocks.push({ type: 'heading', text: heading[1] });
      return;
    }
    if (unorderedItem || orderedItem) {
      flushParagraph();
      const nextListType = unorderedItem ? 'unordered' : 'ordered';
      if (listType && listType !== nextListType) flushList();
      listType = nextListType;
      listItems.push((unorderedItem || orderedItem)[1]);
      return;
    }

    flushList();
    paragraph.push(trimmed);
  });

  flushParagraph();
  flushList();

  return (
    <div className="space-y-3 text-sm leading-7 text-slate-300">
      {blocks.map((block, index) => {
        if (block.type === 'heading') {
          return <h4 key={index} className="pt-1 text-sm font-bold text-slate-100">{renderInline(block.text)}</h4>;
        }
        if (block.type === 'unordered' || block.type === 'ordered') {
          const List = block.type === 'unordered' ? 'ul' : 'ol';
          return (
            <List key={index} className={`${block.type === 'unordered' ? 'list-disc' : 'list-decimal'} space-y-1.5 pl-5 marker:text-blue-400`}>
              {block.items.map((item, itemIndex) => <li key={itemIndex} className="pl-1">{renderInline(item)}</li>)}
            </List>
          );
        }
        return <p key={index}>{renderInline(block.text)}</p>;
      })}
    </div>
  );
}

export function GroqAssistant({ scanData }) {
  const [summary, setSummary] = useState('');
  const [messages, setMessages] = useState([]);
  const [question, setQuestion] = useState('');
  const [pending, setPending] = useState('');
  const [error, setError] = useState('');

  const handleSummary = async () => {
    setPending('summary');
    setError('');
    try {
      setSummary(await generateAiSummary(scanData.id));
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setPending('');
    }
  };

  const handleChat = async (event) => {
    event.preventDefault();
    const prompt = question.trim();
    if (!prompt || pending) return;

    const priorMessages = messages.map(({ role, content }) => ({ role, content }));
    setMessages((current) => [...current, { role: 'user', content: prompt }]);
    setQuestion('');
    setPending('chat');
    setError('');
    try {
      const answer = await askAiAboutScan(scanData.id, prompt, priorMessages.slice(-8));
      setMessages((current) => [...current, { role: 'assistant', content: answer }]);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setPending('');
    }
  };

  return (
    <section className="bg-[#101726] border border-[#1b253b] rounded-xl p-5 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-bold text-slate-100">Groq scan assistant</h3>
          <p className="text-[11px] text-slate-400 mt-1">
            AI responses are advisory and grounded in this scan's OSV findings and metrics.
          </p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={handleSummary}
          disabled={Boolean(pending)}
          className="px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold"
        >
          {pending === 'summary' ? 'Generating explanation…' : 'Explain scan and recommend actions'}
        </button>
        {summary && (
          <div className="basis-full overflow-hidden rounded-xl border border-blue-500/20 bg-gradient-to-br from-blue-500/[0.07] to-[#0d1320]">
            <div className="flex items-center justify-between gap-3 border-b border-[#253659] px-4 py-3">
              <div>
                <h4 className="text-sm font-semibold text-slate-100">AI scan recommendations</h4>
                <p className="mt-0.5 text-[11px] text-slate-400">Prioritized guidance based on this scan</p>
              </div>
              <span className="rounded-full border border-blue-400/20 bg-blue-400/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wide text-blue-300">
                Advisory
              </span>
            </div>
            <div className="max-h-[32rem] overflow-y-auto px-5 py-4">
              <MarkdownContent content={summary} />
            </div>
          </div>
        )}
      </div>

      <div className="space-y-3">
        {messages.length > 0 && (
          <div className="max-h-72 overflow-y-auto space-y-3" aria-live="polite">
            {messages.map((message, index) => (
              <div
                key={`${index}-${message.role}`}
                className={`rounded-lg p-3 text-sm whitespace-pre-wrap leading-relaxed ${
                  message.role === 'user'
                    ? 'ml-8 bg-blue-500/10 border border-blue-500/20 text-blue-100'
                    : 'mr-8 bg-[#0d1320] border border-[#253659] text-slate-200'
                }`}
              >
                <div className="mb-1 text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  {message.role === 'user' ? 'You' : 'Groq'}
                </div>
                {message.role === 'assistant'
                  ? <MarkdownContent content={message.content} />
                  : message.content}
              </div>
            ))}
            {pending === 'chat' && <p className="text-xs text-slate-400">Groq is responding…</p>}
          </div>
        )}
        <form onSubmit={handleChat} className="flex flex-col sm:flex-row gap-2">
          <input
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            maxLength={1000}
            placeholder="Ask about a finding, risk score, or remediation…"
            aria-label="Ask Groq about this scan"
            className="min-w-0 flex-1 rounded-lg bg-[#0d1320] border border-[#253659] px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
          />
          <button
            type="submit"
            disabled={!question.trim() || Boolean(pending)}
            className="px-4 py-2 rounded-lg bg-[#162138] hover:bg-[#1f2e4c] border border-[#253659] disabled:opacity-50 text-xs font-semibold text-slate-100"
          >
            Ask Groq
          </button>
        </form>
      </div>

      {error && (
        <p role="alert" className="text-xs text-red-300">
          {error}
        </p>
      )}
    </section>
  );
}
