import { storeReceiptState, loadReceiptState } from '../chat/sync';
import { waitForSendCapacity } from '../chat/send-capacity';
import { selectPreparationBatch } from '../chat/preparation-batch';
import { applyReceiptUpdates } from '../chat/receipt-updates';
import { observeMessageLayout } from '../ui/message-layout';
import { MessageBubble } from './MessageBubble';
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import type { IDBPDatabase } from 'idb';
import type { CurrentSessionResponse } from '../../shared/contracts/session';
import { uuidv7 } from '../../shared/ids/uuidv7';
import {
  completeExistingLogin,
  completeNewDeviceLogin,
  getCurrentSession,
  logout,
  passwordLoginExisting,
  passwordLoginNewDevice,
  portableKeyLoginExisting,
  portableKeyLoginNewDevice,
  prepareExistingLogin,
  prepareNewDeviceLogin,
  type PreparedExistingLogin,
  type PreparedNewPasskey,
} from '../auth/api';
import { clearGuestDeviceMarker, loadGuestDeviceIds } from '../auth/guest-device';
import { abortAttachmentHttp } from '../attachments/api';
import type { AttachmentDescriptor } from '../attachments/crypto';
import { uploadAttachmentForMessage } from '../attachments/message';
import { ALLOWED_ATTACHMENT_ACCEPT, validateAttachmentFile } from '../attachments/policy';
import { MAX_ATTACHMENTS_PER_MESSAGE } from '../../shared/contracts/attachments';
import { useWallpaperObjectUrl } from '../appearance/use-wallpaper-url';
import {
  getSharedChatWallpaper,
  setSharedChatWallpaper,
  setSharedCustomChatWallpaper,
} from '../appearance/api';
import {
  DEFAULT_CHAT_WALLPAPER,
  wallpaperClassName,
  type ChatWallpaper,
} from '../appearance/wallpaper';
import { listChats, type ChatSummary } from '../chat/api';
import { decodeMessageContent, encodeMessageContent } from '../chat/content';
import { materializeMessageMutations } from '../chat/message-view';
import { scheduleDeliveredReceipts } from '../chat/receipts';
import { applyRealtimeCommittedMessage } from '../chat/realtime-receive';
import {
  prepareSecureChatMessages,
  refreshRejectedSecureChatMessage,
  warmSecureChatSendContext,
} from '../chat/secure-send';
import { committedDisplayCacheKey, loadChatFromEncryptedCache, synchronizeChat, type DisplayMessage } from '../chat/sync';
import { deliverPreparedMessageWsFirst, resumePendingOutboxWsFirst } from '../chat/ws-first-send';
import { BrowserSecureMessagingEngine } from '../crypto/engine';
import { enablePushNotifications } from '../push/subscription';
import { openLocalDatabase } from '../storage/db';
import { advanceChatSyncCursor, compareMessageOrder } from '../storage/message-cache';
import type { JsonSetting, LocalDbSchema, PendingOutboxRecord } from '../storage/schema';
import { ApiError } from '../transport/api';
import { ChatRealtimeClient, type ConnectivityState } from '../transport/realtime';
import { friendlyError } from '../ui/errors';
import { useMobileNavigation } from '../ui/use-mobile-navigation';
import { AccountSecurityPanel, type AccountPanelSection } from './AccountSecurityPanel';
import { AppOptionsMenu } from './AppOptionsMenu';
import { AttachmentPreviewModal, type AttachmentPreviewSource } from './AttachmentPreviewModal';
import { GuestAccountModal } from './GuestAccountModal';
import '../ui/styles.css';
import '../ui/secure-app.css';
import '../ui/attachment-preview.css';
import '../ui/wallpaper.css';
import '../ui/workspace-overlays.css';

type AppState = 'BOOTING' | 'SIGNED_OUT' | 'CRYPTO_MISSING' | 'READY' | 'ERROR';
type UiDeliveryState = 'PENDING' | 'SENT' | 'RETRYING' | 'FAILED';
export type UiMessage = Omit<DisplayMessage, 'plaintext'> & { text: string; attachments: AttachmentDescriptor[]; delivery_state?: UiDeliveryState; edited?: boolean; deleted?: boolean };
type PreparedAttachment = { descriptor: AttachmentDescriptor; name: string; file: File };
type QueuedMessage = {
  chatId: string;
  clientMessageId: string;
  text: string;
  attachments: AttachmentDescriptor[];
  mutation?: { target_message_id: string; type: 'EDIT' | 'TOMBSTONE' };
  replyToMessageId?: string;
};

// Workspace discovery has no realtime channel; refresh visible clients promptly.
const ADMIN_CHAT_REFRESH_MS = 5_000;

export function SecureApp() {
  const [db, setDb] = useState<IDBPDatabase<LocalDbSchema> | null>(null);
  const [appState, setAppState] = useState<AppState>('BOOTING');
  const [session, setSession] = useState<CurrentSessionResponse | null>(null);
  const [chats, setChats] = useState<ChatSummary[]>([]);
  const [selectedChat, setSelectedChat] = useState<string | null>(null);
  const [messages, setMessages] = useState<UiMessage[]>([]);
  const messagesById = useMemo(() => new Map(messages.filter(message => message.message_id).map(message => [message.message_id!, message])), [messages]);
  const [connectivity, setConnectivity] = useState<ConnectivityState>('HTTP_SYNC');
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [localDeviceIds, setLocalDeviceIds] = useState<string[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState('');
  const [loginName, setLoginName] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [preparedExistingPasskey, setPreparedExistingPasskey] = useState<PreparedExistingLogin | null>(null);
  const [preparedNewPasskey, setPreparedNewPasskey] = useState<PreparedNewPasskey | null>(null);
  const [deviceName, setDeviceName] = useState(() => navigator.platform || 'Navegador');
  const [pushState, setPushState] = useState<'IDLE' | 'ENABLED' | 'UNAVAILABLE'>('IDLE');
  const [pushBusy, setPushBusy] = useState(false);
  const [pushMessage, setPushMessage] = useState<string | null>(null);
  const [securityOpen, setSecurityOpen] = useState(false);
  const [accountPanelSection, setAccountPanelSection] = useState<AccountPanelSection>('appearance');
  const [optionsMenuOpen, setOptionsMenuOpen] = useState(false);
  const [guestAccountChatId, setGuestAccountChatId] = useState<string | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [preparedAttachments, setPreparedAttachments] = useState<PreparedAttachment[]>([]);
  const [queuedMessageCount, setQueuedMessageCount] = useState(0);
  const [sendQueuePaused, setSendQueuePaused] = useState(false);
  const [unreadMessageCount, setUnreadMessageCount] = useState(0);
  const [unreadChatIds, setUnreadChatIds] = useState<Set<string>>(() => new Set());
  const [replyingTo, setReplyingTo] = useState<UiMessage | null>(null);
  const [uploadProgress, setUploadProgress] = useState<{ name: string; percent: number } | null>(null);
  const [unavailableHistoryCount, setUnavailableHistoryCount] = useState(0);
  const [chatWallpaper, setChatWallpaper] = useState<ChatWallpaper>(DEFAULT_CHAT_WALLPAPER);
  const wallpaperObjectUrl = useWallpaperObjectUrl(chatWallpaper);
  const [canManageChatWallpaper, setCanManageChatWallpaper] = useState(false);
  const [attachmentPreview, setAttachmentPreview] = useState<AttachmentPreviewSource | null>(null);
  const mobileNavigation = useMobileNavigation(
    mobileMenuOpen || optionsMenuOpen || securityOpen,
    () => setMobileMenuOpen(true),
    () => { setMobileMenuOpen(false); setOptionsMenuOpen(false); setSecurityOpen(false); },
  );
  const realtimeRef = useRef<ChatRealtimeClient | null>(null);
  const realtimeChatIdRef = useRef<string | null>(null);
  const chatListRefreshRef = useRef<Promise<void> | null>(null);
  const syncRefs = useRef(new Map<string, Promise<number>>());
  const revisionRefs = useRef(new Map<string, number>());
  const selectedChatRef = useRef<string | null>(null);
  const sendQueueRef = useRef<QueuedMessage[]>([]);
  const sendingRef = useRef(false);
  const deliveriesRef = useRef(new Set<Promise<void>>());
  const sendQueuePausedRef = useRef(false);
  const drainSendQueueRef = useRef<() => void>(() => undefined);
  const messagesRef = useRef<HTMLDivElement | null>(null);
  const renderedChatsRef = useRef(new Map<string, UiMessage[]>());
  const optimisticMessagesRef = useRef(new Map<string, UiMessage>());
  const localAttachmentFilesRef = useRef(new Map<string, File>());
  const messageCountRef = useRef(0);
  const stickToBottomRef = useRef(true);
  const forceScrollToBottomRef = useRef(true);

  const renderMessages = useCallback((source: DisplayMessage[], mode: 'replace' | 'merge' = 'replace') => {
    const decoded = source.map((message) => {
      try {
        const content = decodeMessageContent(message.plaintext);
        const optimistic = optimisticMessagesRef.current.get(message.client_message_id);
        if (message.revision > 0) optimisticMessagesRef.current.delete(message.client_message_id);
        return {
          ...message,
          text: content.text,
          attachments: content.attachments,
          ...(message.revision === 0 && optimistic?.delivery_state ? { delivery_state: optimistic.delivery_state } : {}),
        };
      } finally {
        message.plaintext.fill(0);
      }
    });
    const chatId = decoded[0]?.chat_id ?? selectedChatRef.current;
    const incomingIds = new Set(decoded.map((message) => message.client_message_id));
    const confirmed = mode === 'merge' && chatId
      ? [...(renderedChatsRef.current.get(chatId) ?? [])].filter((message) => !incomingIds.has(message.client_message_id))
      : [];
    const serverMessages = [...confirmed, ...decoded];
    const present = new Set(serverMessages.map((message) => message.client_message_id));
    const optimistic = chatId
      ? [...optimisticMessagesRef.current.values()].filter((message) => message.chat_id === chatId && !present.has(message.client_message_id))
      : [];
    const ordered = [...serverMessages, ...optimistic].sort(compareMessageOrder);
    const next = materializeMessageMutations(ordered);
    const added = Math.max(0, next.length - messageCountRef.current);
    messageCountRef.current = next.length;
    if (added > 0 && !stickToBottomRef.current && !forceScrollToBottomRef.current) {
      setUnreadMessageCount((count) => count + added);
    }
    if (chatId) renderedChatsRef.current.set(chatId, next);
    setMessages(next);
  }, []);

  const refreshChats = useCallback((): Promise<void> => {
    if (chatListRefreshRef.current) return chatListRefreshRef.current;
    const task = (async () => {
      const next = await listChats();
      setChats((current) => {
        const previous = new Map(current.map((chat) => [chat.chat_id, chat.message_revision]));
        setUnreadChatIds((unread) => {
          const updated = new Set(unread);
          for (const chat of next) {
            if (chat.chat_id !== selectedChatRef.current && chat.message_revision > (previous.get(chat.chat_id) ?? chat.message_revision)) updated.add(chat.chat_id);
          }
          return updated;
        });
        return next;
      });
      const requested = new URLSearchParams(window.location.search).get('chat');
      const preferred = requested && next.some((chat) => chat.chat_id === requested) ? requested : next[0]?.chat_id ?? null;
      setSelectedChat((current) => {
        const selected = current && next.some((chat) => chat.chat_id === current) ? current : preferred;
        selectedChatRef.current = selected;
        return selected;
      });
    })().finally(() => { chatListRefreshRef.current = null; });
    chatListRefreshRef.current = task;
    return task;
  }, []);

  const bootstrap = useCallback(async (database: IDBPDatabase<LocalDbSchema>) => {
    setAppState('BOOTING');
    setError(null);
    try {
      const current = await getCurrentSession();
      setSession(current);
      const identity = await database.get('device_identity', current.device_id);
      if (!identity || !identity.local_master_key) {
        setAppState('CRYPTO_MISSING');
        return;
      }
      const engine = new BrowserSecureMessagingEngine(database, current.user_id, current.device_id);
      await engine.publishPreKeyBundle();
      if (!current.device_authorized) {
        setError('El servidor no habilitó este navegador después de autenticarlo. Cerrá sesión e intentá nuevamente.');
        setAppState('ERROR');
        return;
      }
      await refreshChats();
      setAppState('READY');
    } catch (cause) {
      if (cause instanceof ApiError && (cause.status === 401 || cause.type === 'DEVICE_REVOKED')) {
        setSession(null);
        setError(cause.type === 'SESSION_REQUIRED' ? null : friendlyError(cause));
        const identities = await database.getAll('device_identity');
        const ids = identities.map((identity) => identity.local_device_id);
        setLocalDeviceIds(ids);
        setSelectedDeviceId((current) => ids.includes(current) ? current : '');
        setPreparedExistingPasskey(null);
        setPreparedNewPasskey(null);
        setAppState('SIGNED_OUT');
        return;
      }
      setError(describeError(cause));
      setAppState('ERROR');
    }
  }, [refreshChats]);

  useEffect(() => {
    let active = true;
    void openLocalDatabase().then((database) => {
      if (!active) { database.close(); return; }
      setDb(database);
      return bootstrap(database);
    }).catch((cause) => {
      if (!active) return;
      setError(describeError(cause));
      setAppState('ERROR');
    });
    return () => { active = false; };
  }, [bootstrap]);

  useEffect(() => {
    if (!selectedChat || appState !== 'READY' || !db || !session) {
      setChatWallpaper(DEFAULT_CHAT_WALLPAPER);
      setCanManageChatWallpaper(false);
      return;
    }
    let active = true;
    let cached: Awaited<ReturnType<typeof getSharedChatWallpaper>> | undefined;
    const refreshWallpaper = async () => {
      try {
        const result = await getSharedChatWallpaper(db, session, selectedChat, cached);
        cached = result;
        if (!active) return;
        setChatWallpaper(result.wallpaper);
        setCanManageChatWallpaper(result.canManage);
      } catch (cause) {
        if (active) setError(describeError(cause));
      }
    };
    const refreshIfVisible = () => {
      if (document.visibilityState === 'visible' && navigator.onLine) void refreshWallpaper();
    };
    const interval = globalThis.setInterval(() => {
      if (document.visibilityState === 'visible' && navigator.onLine) void refreshWallpaper();
    }, ADMIN_CHAT_REFRESH_MS);
    void refreshWallpaper();
    document.addEventListener('visibilitychange', refreshIfVisible);
    return () => {
      active = false;
      globalThis.clearInterval(interval);
      document.removeEventListener('visibilitychange', refreshIfVisible);
    };
  }, [selectedChat, appState, db, session]);

  useEffect(() => {
    setPreparedExistingPasskey(null);
  }, [selectedDeviceId]);

  const syncSelected = useCallback(async (chatId: string): Promise<number> => {
    if (!db || !session) return revisionRefs.current.get(chatId) ?? 0;
    const existing = syncRefs.current.get(chatId);
    if (existing) return existing;
    const task = (async () => {
      try {
        const incremental = renderedChatsRef.current.has(chatId);
        const result = await synchronizeChat(db, session, chatId, { incremental, afterRevision: revisionRefs.current.get(chatId) ?? 0 });
        if (selectedChatRef.current === chatId) {
          if (!incremental || result.messages.length) renderMessages(result.messages, incremental ? 'merge' : 'replace');
          if (result.receiptUpdates?.length) {
            const updates = result.receiptUpdates;
            const rendered = renderedChatsRef.current.get(chatId);
            if (rendered) renderedChatsRef.current.set(chatId, applyReceiptUpdates(rendered, updates));
            for (const [id, optimistic] of optimisticMessagesRef.current) {
              if (optimistic.chat_id === chatId) optimisticMessagesRef.current.set(id, applyReceiptUpdates([optimistic], updates)[0]!);
            }
            // The visible state can contain optimistic messages not yet in the
            // rendered cache. Patch it directly instead of replacing it.
            setMessages(current => applyReceiptUpdates(current, updates));
          }
          if (result.unavailableMessageCount > 0) {
            setUnavailableHistoryCount((count) => count + result.unavailableMessageCount);
          }
        }
        revisionRefs.current.set(chatId, result.revision);
        setError(null);
        return result.revision;
      } catch (cause) {
        try {
          const cached = await loadChatFromEncryptedCache(db, session.device_id, chatId, revisionRefs.current.get(chatId) ?? 0);
          if (selectedChatRef.current === chatId) renderMessages(cached.messages, 'merge');
        } catch {}
        throw cause;
      } finally {
        syncRefs.current.delete(chatId);
      }
    })();
    syncRefs.current.set(chatId, task);
    return task;
  }, [db, session, renderMessages]);

  useEffect(() => {
    if (appState !== 'READY' || session?.role !== 'ADMIN') return;
    const refreshIfVisible = () => {
      if (document.visibilityState === 'visible' && navigator.onLine) void refreshChats().catch(() => undefined);
    };
    const timer = window.setInterval(refreshIfVisible, ADMIN_CHAT_REFRESH_MS);
    window.addEventListener('focus', refreshIfVisible);
    window.addEventListener('online', refreshIfVisible);
    document.addEventListener('visibilitychange', refreshIfVisible);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener('focus', refreshIfVisible);
      window.removeEventListener('online', refreshIfVisible);
      document.removeEventListener('visibilitychange', refreshIfVisible);
    };
  }, [appState, session?.role, refreshChats]);

  useEffect(() => {
    selectedChatRef.current = selectedChat;
    messageCountRef.current = 0;
    stickToBottomRef.current = true;
    forceScrollToBottomRef.current = true;
    setUnreadMessageCount(0);
    setUnavailableHistoryCount(0);
    if (!selectedChat) {
      setMessages([]);
      return;
    }
    const confirmed = renderedChatsRef.current.get(selectedChat) ?? [];
    const present = new Set(confirmed.map((message) => message.client_message_id));
    const optimistic = [...optimisticMessagesRef.current.values()]
      .filter((message) => message.chat_id === selectedChat && !present.has(message.client_message_id));
    const next = materializeMessageMutations([...confirmed, ...optimistic].sort(compareMessageOrder));
    messageCountRef.current = next.length;
    setMessages(next);
  }, [selectedChat]);

  useEffect(() => {
    if (appState !== 'READY' || !selectedChat || !db || !session) return;
    void warmSecureChatSendContext(db, {
      chat_id: selectedChat,
      sender_user_id: session.user_id,
      sender_device_id: session.device_id,
    }).catch(() => undefined);
  }, [appState, selectedChat, db, session]);

  useEffect(() => {
    if (appState !== 'READY' || !messagesRef.current) return;
    return observeMessageLayout(messagesRef.current);
  }, [appState, selectedChat]);

  useLayoutEffect(() => {
    const container = messagesRef.current;
    if (!container || (!stickToBottomRef.current && !forceScrollToBottomRef.current)) return;
    container.scrollTop = container.scrollHeight;
    forceScrollToBottomRef.current = false;
    stickToBottomRef.current = true;
    setUnreadMessageCount(0);
  }, [messages]);

  useEffect(() => {
    const viewport = window.visualViewport;
    const updateViewport = () => {
      const height = viewport?.height ?? window.innerHeight;
      const offset = viewport?.offsetTop ?? 0;
      document.documentElement.style.setProperty('--ratchet-viewport-height', `${Math.round(height)}px`);
      document.documentElement.style.setProperty('--ratchet-viewport-offset', `${Math.round(offset)}px`);
    };
    updateViewport();
    viewport?.addEventListener('resize', updateViewport);
    viewport?.addEventListener('scroll', updateViewport);
    window.addEventListener('resize', updateViewport);
    return () => {
      viewport?.removeEventListener('resize', updateViewport);
      viewport?.removeEventListener('scroll', updateViewport);
      window.removeEventListener('resize', updateViewport);
      document.documentElement.style.removeProperty('--ratchet-viewport-height');
      document.documentElement.style.removeProperty('--ratchet-viewport-offset');
    };
  }, []);

  const applySendCompletion = useCallback((
    clientMessageId: string,
    result: PendingOutboxRecord,
    attachments: readonly AttachmentDescriptor[] = [],
  ) => {
    const deliveryState: UiDeliveryState = result.status === 'COMMITTED'
      ? 'SENT'
      : result.status === 'FAILED'
        ? 'FAILED'
        : 'RETRYING';
    const transform = (message: UiMessage): UiMessage => {
      if (message.client_message_id !== clientMessageId) return message;
      const revision = result.status === 'COMMITTED' && result.server_revision !== undefined
        ? result.server_revision
        : message.revision;
      return {
        ...message,
        delivery_state: deliveryState,
        revision,
        message_id: result.server_message_id ?? message.message_id,
        cache_key: result.status === 'COMMITTED' && revision > 0
          ? committedDisplayCacheKey(`outgoing:${clientMessageId}`, revision)
          : message.cache_key,
      };
    };

    const optimistic = optimisticMessagesRef.current.get(clientMessageId);
    if (optimistic) optimisticMessagesRef.current.set(clientMessageId, transform(optimistic));

    const rendered = renderedChatsRef.current.get(result.chat_id);
    if (rendered) renderedChatsRef.current.set(result.chat_id, rendered.map(transform).sort(compareMessageOrder));
    if (selectedChatRef.current === result.chat_id) {
      setMessages((current) => current.map(transform).sort(compareMessageOrder));
    }

    if (result.status === 'COMMITTED') {
      for (const attachment of attachments) localAttachmentFilesRef.current.delete(attachment.file_id);
    }
  }, []);

  const deliverPrepared = useCallback(async (record: PendingOutboxRecord): Promise<PendingOutboxRecord> => {
    if (!db || !session) return record;
    let current = record;
    for (let refreshRound = 0; refreshRound < 3; refreshRound += 1) {
      const realtime = realtimeChatIdRef.current === current.chat_id ? realtimeRef.current : null;
      current = await deliverPreparedMessageWsFirst(db, realtime, current);
      if (current.status !== 'NEEDS_REENCRYPT') return current;
      current = await refreshRejectedSecureChatMessage(db, {
        chat_id: current.chat_id,
        sender_user_id: session.user_id,
        sender_device_id: session.device_id,
        client_message_id: current.client_message_id,
      });
    }
    return current;
  }, [db, session]);

  const recoverChatOutbox = useCallback(async (chatId: string): Promise<void> => {
    if (!db || !session || !navigator.onLine) return;
    const rejected = (await db.getAllFromIndex('pending_outbox', 'by-chat', chatId))
      .filter((record) => record.status === 'NEEDS_REENCRYPT')
      .sort((left, right) => (left.request.sender_sequence ?? Number.MAX_SAFE_INTEGER) - (right.request.sender_sequence ?? Number.MAX_SAFE_INTEGER));
    for (const record of rejected) {
      const refreshed = await refreshRejectedSecureChatMessage(db, {
        chat_id: chatId,
        sender_user_id: session.user_id,
        sender_device_id: session.device_id,
        client_message_id: record.client_message_id,
      });
      const result = await deliverPrepared(refreshed);
      applySendCompletion(record.client_message_id, result);
      if (result.status !== 'COMMITTED') return;
    }

    const realtime = realtimeChatIdRef.current === chatId ? realtimeRef.current : null;
    await resumePendingOutboxWsFirst(db, realtime, chatId, (result) => {
      applySendCompletion(result.client_message_id, result);
    });
  }, [db, session, deliverPrepared, applySendCompletion]);

  useEffect(() => {
    realtimeRef.current?.stop();
    realtimeRef.current = null;
    realtimeChatIdRef.current = null;
    if (appState !== 'READY' || !selectedChat || !db || !session) return;
    let cancelled = false;
    void (async () => {
      try {
        const cached = await loadChatFromEncryptedCache(db, session.device_id, selectedChat, revisionRefs.current.get(selectedChat) ?? 0);
        if (!cancelled && selectedChatRef.current === selectedChat) renderMessages(cached.messages);
      } catch {}
      return syncSelected(selectedChat);
    })().then((initialRevision) => {
      if (cancelled) return;
      const realtime = new ChatRealtimeClient({
        chatId: selectedChat,
        initialRevision,
        syncHttp: () => syncSelected(selectedChat),
        onState: setConnectivity,
        onReceipt: async (event) => {
          if (event.user_id !== session.user_id) {
            await storeReceiptState(db, event.message_id, event.state);
            const updates = [{ message_id: event.message_id, state: (await loadReceiptState(db, event.message_id))! }];
            const rendered = renderedChatsRef.current.get(event.chat_id);
            if (rendered) renderedChatsRef.current.set(event.chat_id, applyReceiptUpdates(rendered, updates));
            for (const [id, optimistic] of optimisticMessagesRef.current) if (optimistic.chat_id === event.chat_id) optimisticMessagesRef.current.set(id, applyReceiptUpdates([optimistic], updates)[0]!);
            if (selectedChatRef.current === event.chat_id) setMessages(current => applyReceiptUpdates(current, updates));
          }
          await advanceChatSyncCursor(db, event.chat_id, event.revision);
          revisionRefs.current.set(event.chat_id, event.revision);
        },
        onContiguousOwnCommit: async (ack) => {
          await advanceChatSyncCursor(db, selectedChat, ack.revision);
          revisionRefs.current.set(selectedChat, ack.revision);
          setChats((current) => current.map((chat) => chat.chat_id === selectedChat
            ? { ...chat, revision: Math.max(chat.revision, ack.revision) }
            : chat));
        },
        onCommittedMessage: async (event) => {
          const display = await applyRealtimeCommittedMessage(db, session, event);
          scheduleDeliveredReceipts(db, event.chat_id, [display]);
          revisionRefs.current.set(event.chat_id, event.revision);
          setChats((current) => current.map((chat) => chat.chat_id === event.chat_id
            ? { ...chat, revision: Math.max(chat.revision, event.revision) }
            : chat));
          if (selectedChatRef.current === event.chat_id) renderMessages([display], 'merge');
          else display.plaintext.fill(0);
        },
        onEvent: (event) => {
          if (!('revision' in event)) return;
          setChats((current) => current.map((chat) => chat.chat_id === event.chat_id
            ? { ...chat, revision: Math.max(chat.revision, event.revision) }
            : chat));
        },
      });
      realtimeRef.current = realtime;
      realtimeChatIdRef.current = selectedChat;
      realtime.start();
      void recoverChatOutbox(selectedChat).catch((cause) => {
        if (!cancelled) setError(describeError(cause));
      });
    }).catch((cause) => { if (!cancelled) setError(describeError(cause)); });
    return () => {
      cancelled = true;
      realtimeRef.current?.stop();
      realtimeRef.current = null;
      realtimeChatIdRef.current = null;
    };
  }, [appState, selectedChat, db, session, syncSelected, renderMessages, recoverChatOutbox]);

  useEffect(() => {
    if (appState !== 'READY' || !selectedChat || !db || !session || connectivity === 'OFFLINE') return;
    void recoverChatOutbox(selectedChat).catch((cause) => setError(describeError(cause)));
  }, [appState, connectivity, selectedChat, db, session, recoverChatOutbox]);

  useEffect(() => {
    const online = () => {
      realtimeRef.current?.notifyOnline();
      const chatId = selectedChatRef.current;
      if (chatId) void recoverChatOutbox(chatId).catch((cause) => setError(describeError(cause)));
    };
    const offline = () => realtimeRef.current?.notifyOffline();
    window.addEventListener('online', online);
    window.addEventListener('offline', offline);
    return () => { window.removeEventListener('online', online); window.removeEventListener('offline', offline); };
  }, [recoverChatOutbox]);

  const drainSendQueue = useCallback(async () => {
    if (!db || !session || sendingRef.current) return;
    sendingRef.current = true;
    sendQueuePausedRef.current = false;
    setSendQueuePaused(false);
    try {
      while (sendQueueRef.current.length > 0 && !sendQueuePausedRef.current) {
        await waitForSendCapacity(deliveriesRef.current, 8);
        if (!sendQueueRef.current.length || sendQueuePausedRef.current) break;
        const pendingBatch = selectPreparationBatch(sendQueueRef.current.slice(0, 8 - deliveriesRef.current.size));
        const plaintexts = pendingBatch.map(pending => encodeMessageContent(pending.text, pending.attachments));
        try {
          const records = await prepareSecureChatMessages(db, pendingBatch.map((pending, index) => ({
            chat_id: pending.chatId,
            sender_user_id: session.user_id,
            sender_device_id: session.device_id,
            client_message_id: pending.clientMessageId,
            plaintext: plaintexts[index]!,
            attachment_ids: pending.attachments.map(entry => entry.file_id),
            ...(pending.mutation ? { mutation: pending.mutation } : {}),
            ...(pending.replyToMessageId ? { reply_to_message_id: pending.replyToMessageId } : {}),
          })));
          sendQueueRef.current.splice(0, records.length);
          setQueuedMessageCount(sendQueueRef.current.length);
          for (const [index, queued] of records.entries()) {
            const pending = pendingBatch[index]!;
            const delivery = deliverPrepared(queued)
              .then(result => applySendCompletion(pending.clientMessageId, result, pending.attachments))
              .catch(async cause => {
                const current = await db.get('pending_outbox', pending.clientMessageId).catch(() => undefined);
                if (current) applySendCompletion(pending.clientMessageId, current, pending.attachments);
                setError(describeError(cause));
              }).finally(() => { deliveriesRef.current.delete(delivery); });
            deliveriesRef.current.add(delivery);
          }
        } catch (cause) {
          sendQueuePausedRef.current = true;
          setSendQueuePaused(true);
          setError(describeError(cause));
          break;
        } finally {
          plaintexts.forEach(plaintext => plaintext.fill(0));
        }
      }
    } finally {
      sendingRef.current = false;
      if (sendQueueRef.current.length > 0 && !sendQueuePausedRef.current) {
        queueMicrotask(() => drainSendQueueRef.current());
      }
    }
  }, [db, session, deliverPrepared, applySendCompletion]);
  drainSendQueueRef.current = () => { void drainSendQueue(); };

  const enqueueMessage = () => {
    if (!selectedChat || !session || (!draft.trim() && preparedAttachments.length === 0) || busy) return;
    const clientMessageId = uuidv7();
    const text = draft.trim();
    const attachments = preparedAttachments.map((entry) => entry.descriptor);
    sendQueueRef.current.push({
      chatId: selectedChat,
      clientMessageId,
      text,
      attachments,
      ...(replyingTo?.message_id ? { replyToMessageId: replyingTo.message_id } : {}),
    });
    const optimistic: UiMessage = {
      cache_key: `outgoing:${clientMessageId}`,
      chat_id: selectedChat,
      revision: 0,
      direction: 'OUTGOING',
      message_id: null,
      client_message_id: clientMessageId,
      sender_user_id: session.user_id,
      sender_device_id: session.device_id,
      sender_display_name: null,
      created_at: new Date().toISOString(),
      text,
      attachments,
      delivery_state: 'PENDING',
      mutation: null,
      receipt_state: null,
      reply_to_message_id: replyingTo?.message_id ?? null,
    };
    optimisticMessagesRef.current.set(clientMessageId, optimistic);
    setMessages((current) => {
      const next = [...current, optimistic].sort(compareMessageOrder);
      messageCountRef.current = next.length;
      return next;
    });
    setDraft('');
    setPreparedAttachments([]);
    setReplyingTo(null);
    setQueuedMessageCount(sendQueueRef.current.length);
    sendQueuePausedRef.current = false;
    setSendQueuePaused(false);
    forceScrollToBottomRef.current = true;
    drainSendQueueRef.current();
  };

  const scrollToLatest = () => {
    const container = messagesRef.current;
    if (!container) return;
    forceScrollToBottomRef.current = false;
    stickToBottomRef.current = true;
    setUnreadMessageCount(0);
    container.scrollTop = container.scrollHeight;
  };

  const uploadFiles = async (files: FileList | null) => {
    if (!files || !db || !session || !selectedChat) return;
    setBusy(true);
    setError(null);
    try {
      const next = [...preparedAttachments];
      const selected = Array.from(files);
      if (next.length + selected.length > MAX_ATTACHMENTS_PER_MESSAGE) throw new Error(`Máximo ${MAX_ATTACHMENTS_PER_MESSAGE} adjuntos por mensaje`);
      for (const file of selected) await validateAttachmentFile(file);
      for (const file of selected) {
        setUploadProgress({ name: file.name, percent: 0 });
        const descriptor = await uploadAttachmentForMessage(db, session.device_id, selectedChat, file, (percent) => {
          setUploadProgress({ name: file.name, percent });
        });
        localAttachmentFilesRef.current.set(descriptor.file_id, file);
        next.push({ descriptor, name: file.name, file });
        setPreparedAttachments([...next]);
      }
      setPreparedAttachments(next);
    } catch (cause) {
      setError(describeError(cause));
    } finally {
      setUploadProgress(null);
      setBusy(false);
    }
  };

  const removePreparedAttachment = async (entry: PreparedAttachment) => {
    try { await abortAttachmentHttp(entry.descriptor.file_id); }
    catch (cause) { setError(describeError(cause)); return; }
    localAttachmentFilesRef.current.delete(entry.descriptor.file_id);
    setPreparedAttachments((items) => items.filter((item) => item.descriptor.file_id !== entry.descriptor.file_id));
  };

  const changeChatWallpaper = async (wallpaper: ChatWallpaper) => {
    if (!selectedChat) throw new Error('Seleccioná una conversación de tu cuenta para cambiar el fondo.');
    if (wallpaper.kind !== 'preset') throw new Error('La imagen personalizada se carga como archivo.');
    const result = await setSharedChatWallpaper(selectedChat, wallpaper.preset);
    setChatWallpaper(result.wallpaper);
    setCanManageChatWallpaper(result.canManage);
  };

  const changeCustomChatWallpaper = async (file: File) => {
    if (!selectedChat) throw new Error('Seleccioná una conversación de tu cuenta para cambiar el fondo.');
    if (!db || !session) throw new Error('La sesión local no está lista.');
    const result = await setSharedCustomChatWallpaper(db, session, selectedChat, file);
    setChatWallpaper(result.wallpaper);
    setCanManageChatWallpaper(result.canManage);
  };

  const mutateMessage = useCallback((message: UiMessage, type: 'EDIT' | 'TOMBSTONE') => {
    if (!selectedChat || !session || !message.message_id || session.role === 'CUSTOMER' || message.deleted) return;
    const text = type === 'EDIT' ? window.prompt('Editar mensaje', message.text)?.trim() : '';
    if (type === 'EDIT' && !text) return;
    if (type === 'TOMBSTONE' && !window.confirm('¿Borrar este mensaje para todos?')) return;
    const clientMessageId = uuidv7();
    const mutation = { target_message_id: message.message_id, type } as const;
    sendQueueRef.current.push({ chatId: selectedChat, clientMessageId, text: text ?? '', attachments: [], mutation });

    // Keep the mutation itself in the optimistic map, not just in React state.
    // Any WS/HTTP render that races the send therefore re-applies the local
    // mutation instead of resurrecting stale server/cache content.
    const optimisticMutation: UiMessage = {
      cache_key: `outgoing:${clientMessageId}`,
      chat_id: selectedChat,
      revision: 0,
      direction: 'OUTGOING',
      message_id: null,
      client_message_id: clientMessageId,
      sender_user_id: session.user_id,
      sender_device_id: session.device_id,
      sender_display_name: null,
      created_at: new Date().toISOString(),
      text: text ?? '',
      attachments: [],
      delivery_state: 'PENDING',
      mutation,
      receipt_state: null,
      reply_to_message_id: null,
    };
    optimisticMessagesRef.current.set(clientMessageId, optimisticMutation);
    setMessages((current) => {
      const next = materializeMessageMutations([...current, optimisticMutation].sort(compareMessageOrder));
      messageCountRef.current = next.length;
      return next;
    });
    if (type === 'TOMBSTONE' && replyingTo?.message_id === message.message_id) setReplyingTo(null);
    setQueuedMessageCount(sendQueueRef.current.length);
    drainSendQueueRef.current();
  }, [selectedChat, session, replyingTo]);

  const doPrepareExistingPasskey = async () => {
    if (!selectedDeviceId) return;
    setBusy(true); setError(null);
    try { setPreparedExistingPasskey(await prepareExistingLogin(selectedDeviceId)); }
    catch (cause) { setError(describeError(cause)); }
    finally { setBusy(false); }
  };

  const doExistingPasskeyLogin = async () => {
    if (!db || !preparedExistingPasskey) return;
    setBusy(true); setError(null);
    try {
      await completeExistingLogin(preparedExistingPasskey);
      setPreparedExistingPasskey(null);
      await bootstrap(db);
    } catch (cause) { setError(describeError(cause)); }
    finally { setBusy(false); }
  };

  const doPrepareNewPasskey = async () => {
    if (!db) return;
    setBusy(true); setError(null);
    try { setPreparedNewPasskey(await prepareNewDeviceLogin(db, deviceName.trim() || 'Navegador')); }
    catch (cause) { setError(describeError(cause)); }
    finally { setBusy(false); }
  };

  const doNewPasskeyLogin = async () => {
    if (!db || !preparedNewPasskey) return;
    setBusy(true); setError(null);
    try {
      const result = await completeNewDeviceLogin(preparedNewPasskey);
      setSelectedDeviceId(result.device_id);
      setPreparedNewPasskey(null);
      await bootstrap(db);
    } catch (cause) { setError(describeError(cause)); }
    finally { setBusy(false); }
  };

  const doPasswordLogin = async () => {
    if (!db) return;
    if (!loginName.trim()) { setError('Ingresá el nombre de usuario.'); return; }
    if (masterPassword.length < 15) { setError('La contraseña debe tener al menos 15 caracteres.'); return; }
    setBusy(true); setError(null);
    try {
      const rememberedDeviceId = await loadRememberedDeviceId(db, loginName);
      let result;
      const localDeviceIds = await loadLocalDeviceCandidates(db, rememberedDeviceId);
      for (const localDeviceId of localDeviceIds) {
        try {
          result = await passwordLoginExisting(loginName, masterPassword, localDeviceId);
          break;
        } catch (cause) {
          if (!(cause instanceof ApiError) || cause.type !== 'DEVICE_NOT_AVAILABLE') throw cause;
        }
      }
      result ??= await passwordLoginNewDevice(db, loginName, masterPassword, deviceName.trim() || 'Navegador');
      await clearGuestDeviceMarker(db, result.device_id);
      await rememberDeviceId(db, loginName, result.device_id);
      setSelectedDeviceId(result.device_id);
      setMasterPassword('');
      await bootstrap(db);
    } catch (cause) { setError(describeError(cause)); }
    finally { setBusy(false); }
  };

  const doPortableKeyLogin = async (file: File) => {
    if (!db) return;
    if (masterPassword.length < 15) { setError('Ingresá la contraseña que cifra el archivo de llave.'); return; }
    setBusy(true); setError(null);
    try {
      if (selectedDeviceId) await portableKeyLoginExisting(file, masterPassword, selectedDeviceId);
      else {
        const result = await portableKeyLoginNewDevice(db, file, masterPassword, deviceName.trim() || 'Navegador');
        setSelectedDeviceId(result.device_id);
      }
      setMasterPassword('');
      await bootstrap(db);
    } catch (cause) { setError(describeError(cause)); }
    finally { setBusy(false); }
  };

  const doLogout = async () => {
    setBusy(true);
    try {
      setAttachmentPreview(null);
      localAttachmentFilesRef.current.clear();
      optimisticMessagesRef.current.clear();
      renderedChatsRef.current.clear();
      sendQueueRef.current = [];
      sendQueuePausedRef.current = false;
      setQueuedMessageCount(0);
      setSendQueuePaused(false);
      setMessages([]);
      await logout();
      realtimeRef.current?.stop();
      realtimeRef.current = null;
      realtimeChatIdRef.current = null;
      setLoginName('');
      setMasterPassword('');
      setSelectedDeviceId('');
      setPreparedExistingPasskey(null);
      setPreparedNewPasskey(null);
      if (db) await bootstrap(db);
    }
    catch (cause) { setError(describeError(cause)); }
    finally { setBusy(false); }
  };

  const enablePush = async () => {
    if (pushBusy) return;
    if (!('Notification' in window) || !('PushManager' in window) || !('serviceWorker' in navigator)) {
      setPushMessage('Este navegador no permite avisos aquí. En iPhone o iPad, agregá Ratchet a la pantalla de inicio desde Safari y abrilo desde ese icono. En otros teléfonos, usá un navegador compatible.');
      return;
    }
    if (Notification.permission === 'denied') {
      setPushMessage('Las notificaciones están bloqueadas. Habilitalas en los permisos de este sitio o de la aplicación y volvé a intentar.');
      return;
    }
    setPushBusy(true);
    setPushMessage(null);
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      // Start the permission prompt directly in the user gesture, before any await.
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') {
        setPushMessage('No se habilitaron los avisos. Podés volver a intentarlo desde Opciones.');
        return;
      }
      const registration = await Promise.race([
        navigator.serviceWorker.ready,
        new Promise<never>((_, reject) => { timeout = setTimeout(() => reject(new Error('La aplicación todavía no está preparada para recibir avisos. Recargá y volvé a intentar.')), 10_000); }),
      ]);
      const result = await enablePushNotifications(registration, permission);
      setPushState(result.enabled ? 'ENABLED' : 'UNAVAILABLE');
      setPushMessage(result.enabled ? 'Recibirás avisos de mensajes nuevos.' : 'El servicio de notificaciones todavía no está habilitado en esta instalación.');
    } catch (cause) { setPushMessage(describeError(cause)); setPushState('UNAVAILABLE'); }
    finally { clearTimeout(timeout); setPushBusy(false); }
  };

  const openAccountPanel = (section: AccountPanelSection) => {
    setAccountPanelSection(section);
    setOptionsMenuOpen(false);
    setSecurityOpen(true);
  };

  if (appState === 'BOOTING') return <Centered title="Abriendo Ratchet…" />;
  if (appState === 'ERROR') return <Centered title="No se pudo iniciar" detail={error || 'Error desconocido'} {...(db ? { action: () => void bootstrap(db) } : {})} />;
  if (appState === 'CRYPTO_MISSING') return <Centered title="Clave de dispositivo no disponible" detail="La sesión del servidor sigue existiendo, pero este navegador perdió la clave del historial local. Volvé a ingresar para recuperar los mensajes del servidor." action={() => void doLogout()} actionLabel="Cerrar sesión" />;
  if (appState === 'SIGNED_OUT') return <AuthScreen localDeviceIds={localDeviceIds} selectedDeviceId={selectedDeviceId} setSelectedDeviceId={setSelectedDeviceId} deviceName={deviceName} setDeviceName={setDeviceName} loginName={loginName} setLoginName={setLoginName} masterPassword={masterPassword} setMasterPassword={setMasterPassword} preparedExistingPasskey={preparedExistingPasskey} preparedNewPasskey={preparedNewPasskey} busy={busy} error={error} onPrepareExistingPasskey={doPrepareExistingPasskey} onExistingPasskeyLogin={doExistingPasskeyLogin} onPrepareNewPasskey={doPrepareNewPasskey} onNewPasskeyLogin={doNewPasskeyLogin} onPasswordLogin={doPasswordLogin} onPortableKeyLogin={doPortableKeyLogin} />;

  if (!db || !session) return <Centered title="Estado inconsistente" detail="La sesión lista perdió su contexto local." />;

  const selectedChatSummary = chats.find((chat) => chat.chat_id === selectedChat) ?? null;
  const selectedWorkspaceRole = selectedChatSummary
    ? session.staff_memberships.find((membership) => membership.workspace_id === selectedChatSummary.workspace_id)?.staff_role ?? null
    : null;
  const canCreateSelectedGuestAccount = selectedChatSummary?.customer_has_account === false
    && (selectedWorkspaceRole === 'ADMIN' || selectedWorkspaceRole === 'OPERATOR');

  return (
    <main className="shell" {...mobileNavigation}>
      <aside className={`sidebar${mobileMenuOpen ? ' mobile-open' : ''}`} role="navigation" aria-label="Navegación principal">
        <div className="brand"><span className="brand-mark">R</span><div><h1>Ratchet</h1><small>{accountLabel(session)}</small></div><button className="mobile-menu-close" onClick={() => setMobileMenuOpen(false)} aria-label="Cerrar menú">×</button></div>
        <div className="chat-list">
          {chats.map((chat) => <button key={chat.chat_id} className={selectedChat === chat.chat_id ? 'chat-item active' : 'chat-item'} onClick={() => { setPreparedAttachments([]); setReplyingTo(null); selectedChatRef.current = chat.chat_id; setSelectedChat(chat.chat_id); setUnreadChatIds((ids) => { const next = new Set(ids); next.delete(chat.chat_id); return next; }); setMobileMenuOpen(false); }}><strong>{session.role === 'CUSTOMER' ? `Chat con ${chat.support_display_name ?? 'Soporte'}` : chat.customer_display_name ?? `Chat ${shortId(chat.chat_id)}`}{unreadChatIds.has(chat.chat_id) && <i className="unread-chat-dot" aria-label="Mensajes nuevos" />}</strong><span>{chat.customer_has_account === false ? 'Invitado' : 'Cliente'}{chat.referred_by_display_name ? ` · llegó por ${chat.referred_by_display_name}` : ''}</span></button>)}
          {chats.length === 0 && <p className="muted">No hay conversaciones todavía.</p>}
        </div>
        <div className="sidebar-footer"><button className="secondary sidebar-options-button" onClick={() => { setMobileMenuOpen(false); setOptionsMenuOpen(true); }}>Opciones</button></div>
      </aside>
      <section className="workspace">
        <header><button className="mobile-menu-button" onClick={() => setMobileMenuOpen(true)} aria-label="Abrir conversaciones">Chats</button><div><strong>{session.role === 'CUSTOMER' ? selectedChatSummary?.support_display_name ?? 'Soporte' : selectedChatSummary?.customer_display_name ?? (selectedChat ? `Chat ${shortId(selectedChat)}` : 'Soporte seguro')}</strong><div className="substatus">{session.role === 'CUSTOMER' ? 'Estamos para ayudarte' : selectedChatSummary?.referred_by_display_name ? `Llegó por ${selectedChatSummary.referred_by_display_name}` : 'Bandeja compartida'}</div></div><div className="workspace-header-actions">{canCreateSelectedGuestAccount && <button className="create-guest-account-button" onClick={() => setGuestAccountChatId(selectedChat)}>Crear cuenta</button>}<span className={`status ${connectivity.toLowerCase()}`}>{connectivityLabel(connectivity)}</span>{<button className="options-menu-button" onClick={() => setOptionsMenuOpen((open) => !open)} aria-haspopup="dialog" aria-expanded={optionsMenuOpen}>Opciones</button>}</div></header>
        {error && <div className="error-banner" role="alert"><span>{error}</span><button aria-label="Cerrar aviso" onClick={() => setError(null)}>×</button></div>}
        {unavailableHistoryCount > 0 && <div className="history-notice" role="note"><strong>Este navegador se agregó después.</strong> {unavailableHistoryCount === 1 ? 'Un mensaje anterior' : `${unavailableHistoryCount} mensajes anteriores`} no estaba cifrado para este dispositivo. Los mensajes nuevos llegan automáticamente.</div>}
        <div className={`messages ${wallpaperClassName(chatWallpaper)}`} style={wallpaperObjectUrl ? { '--chat-wallpaper-image': `url(${JSON.stringify(wallpaperObjectUrl)})` } as CSSProperties : undefined} ref={messagesRef} onScroll={(event) => { const element = event.currentTarget; const atBottom = element.scrollHeight - element.scrollTop - element.clientHeight < 80; stickToBottomRef.current = atBottom; if (atBottom) setUnreadMessageCount(0); }}>
          {!selectedChat && <div className="empty"><h2>Sin conversación seleccionada</h2></div>}
          {selectedChat && messages.length === 0 && <div className="empty"><h2>Sin mensajes todavía</h2><p>Escribí un mensaje para comenzar.</p></div>}
          {messages.map((message) => <MessageBubble key={message.cache_key} message={message} replied={message.reply_to_message_id ? messagesById.get(message.reply_to_message_id) : null} senderLabel={message.sender_user_id === session.user_id ? 'Vos' : message.sender_display_name ?? (session.role === 'CUSTOMER' ? selectedChatSummary?.support_display_name ?? 'Soporte' : selectedChatSummary?.customer_display_name ?? 'Cliente')} isCustomer={session.role === 'CUSTOMER'} localFiles={localAttachmentFilesRef.current} onReply={setReplyingTo} onMutate={mutateMessage} onPreview={setAttachmentPreview} />)}
        </div>
        {unreadMessageCount > 0 && <button className="new-messages-button" onClick={scrollToLatest}>{unreadMessageCount === 1 ? '1 mensaje nuevo' : `${unreadMessageCount} mensajes nuevos`} ↓</button>}
        {selectedChat && <div className="composer-wrap">{replyingTo && <div className="replying-banner"><span><strong>Respondiendo</strong>{replyingTo.text || (replyingTo.attachments.length ? 'Adjunto' : 'Mensaje')}</span><button onClick={() => setReplyingTo(null)} aria-label="Cancelar respuesta">×</button></div>}{uploadProgress && <div className="upload-progress" role="status"><span>Subiendo {uploadProgress.name}</span><progress max={100} value={uploadProgress.percent} /><b>{uploadProgress.percent}%</b></div>}{preparedAttachments.length > 0 && <div className="prepared-attachments">{preparedAttachments.map((entry) => <span key={entry.descriptor.file_id}><button className="prepared-attachment-open" onClick={() => setAttachmentPreview({ kind: 'local', file: entry.file })}>Ver {entry.name}</button><button onClick={() => void removePreparedAttachment(entry)} aria-label={`Quitar ${entry.name}`}>×</button></span>)}</div>}<div className="composer"><label className="attach-button" title="Adjuntar foto o PDF (máximo 10 MB)">＋<input type="file" accept={ALLOWED_ATTACHMENT_ACCEPT} multiple hidden onChange={(event) => { void uploadFiles(event.currentTarget.files); event.currentTarget.value = ''; }} disabled={busy} /></label><textarea value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="Mensaje" rows={1} onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); enqueueMessage(); } }} /><button onPointerDown={(event) => event.preventDefault()} onClick={enqueueMessage} disabled={busy || (!draft.trim() && preparedAttachments.length === 0)}>Enviar</button></div>{queuedMessageCount > 0 && <div className={`send-queue-status${sendQueuePaused ? ' paused' : ''}`} role="status">{sendQueuePaused ? 'Hay mensajes sin preparar.' : 'Protegiendo mensajes…'}{sendQueuePaused && <button onClick={() => { sendQueuePausedRef.current = false; setSendQueuePaused(false); drainSendQueueRef.current(); }}>Reintentar</button>}</div>}</div>}
      </section>
      {optionsMenuOpen && <AppOptionsMenu canManageAgents={session.staff_memberships.some((membership) => membership.staff_role === 'ADMIN')} canCreateReferrals={session.staff_memberships.some((membership) => membership.staff_role === 'ADMIN' || membership.staff_role === 'OPERATOR')} notificationsEnabled={pushState === 'ENABLED'} notificationsBusy={pushBusy} notificationMessage={pushMessage} onOpenSection={openAccountPanel} onEnableNotifications={() => { void enablePush(); }} onLogout={() => { setOptionsMenuOpen(false); void doLogout(); }} onClose={() => setOptionsMenuOpen(false)} />}
      {securityOpen && <AccountSecurityPanel db={db} session={session} selectedChatId={selectedChat} chatWallpaper={chatWallpaper} canManageChatWallpaper={canManageChatWallpaper} initialSection={accountPanelSection} onChatWallpaperChange={changeChatWallpaper} onCustomWallpaperFile={changeCustomChatWallpaper} onSessionChange={setSession} onClose={() => setSecurityOpen(false)} onCurrentDeviceRevoked={() => void doLogout()} />}
      {attachmentPreview && <AttachmentPreviewModal source={attachmentPreview} onClose={() => setAttachmentPreview(null)} />}
      {guestAccountChatId && <GuestAccountModal chatId={guestAccountChatId} accountExists={chats.find((chat) => chat.chat_id === guestAccountChatId)?.customer_has_account === true} canManagePassword={session.staff_memberships.some((membership) => membership.workspace_id === chats.find((chat) => chat.chat_id === guestAccountChatId)?.workspace_id && (membership.staff_role === 'ADMIN' || (chats.find((chat) => chat.chat_id === guestAccountChatId)?.customer_has_account === false && membership.staff_role === 'OPERATOR')))} onCreated={refreshChats} onClose={() => setGuestAccountChatId(null)} />}
    </main>
  );
}

function AuthScreen(props: {
  localDeviceIds: string[];
  selectedDeviceId: string;
  setSelectedDeviceId: (value: string) => void;
  deviceName: string;
  setDeviceName: (value: string) => void;
  loginName: string;
  setLoginName: (value: string) => void;
  masterPassword: string;
  setMasterPassword: (value: string) => void;
  preparedExistingPasskey: PreparedExistingLogin | null;
  preparedNewPasskey: PreparedNewPasskey | null;
  busy: boolean;
  error: string | null;
  onPrepareExistingPasskey: () => Promise<void>;
  onExistingPasskeyLogin: () => Promise<void>;
  onPrepareNewPasskey: () => Promise<void>;
  onNewPasskeyLogin: () => Promise<void>;
  onPasswordLogin: () => Promise<void>;
  onPortableKeyLogin: (file: File) => Promise<void>;
}) {
  const [keyFile, setKeyFile] = useState<File | null>(null);
  return <div className="auth-page"><section className="auth-card"><Brand/><h2>Ingresar</h2><label>Usuario<input autoComplete="username" value={props.loginName} onChange={(event) => props.setLoginName(event.target.value)} /></label><label>Contraseña<input type="password" autoComplete="current-password" value={props.masterPassword} onChange={(event) => props.setMasterPassword(event.target.value)} /></label><button onClick={() => void props.onPasswordLogin()} disabled={props.busy}>{props.busy ? 'Ingresando…' : 'Ingresar'}</button><p className="notice">Ratchet prepara automáticamente la seguridad de este navegador. No requiere aprobación manual.</p><details><summary>Opciones avanzadas</summary><label>Nombre de este navegador<input value={props.deviceName} onChange={(event) => props.setDeviceName(event.target.value)} /></label>{props.localDeviceIds.length > 0 && <label>Identidad local<select value={props.selectedDeviceId} onChange={(event) => props.setSelectedDeviceId(event.target.value)}><option value="">Crear una identidad automáticamente</option>{props.localDeviceIds.map((id) => <option key={id} value={id}>Identidad {shortId(id)}</option>)}</select></label>}<label>Archivo de llave cifrada<input type="file" accept=".ratchet-key,application/json" onChange={(event) => setKeyFile(event.currentTarget.files?.[0] ?? null)} /></label><button className="secondary full" onClick={() => keyFile && void props.onPortableKeyLogin(keyFile)} disabled={props.busy || !keyFile}>{props.busy ? 'Verificando…' : 'Ingresar con archivo de llave'}</button><p className="notice">La llave se descifra y firma localmente; el archivo y su contraseña nunca se envían al servidor.</p>{props.selectedDeviceId && (!props.preparedExistingPasskey ? <button className="secondary full" onClick={() => void props.onPrepareExistingPasskey()} disabled={props.busy}>Preparar acceso con passkey</button> : <button className="secondary full" onClick={() => void props.onExistingPasskeyLogin()} disabled={props.busy}>{props.busy ? 'Verificando…' : 'Ingresar con passkey'}</button>)}{!props.preparedNewPasskey ? <button className="secondary full" onClick={() => void props.onPrepareNewPasskey()} disabled={props.busy}>Preparar passkey para navegador nuevo</button> : <button className="secondary full" onClick={() => void props.onNewPasskeyLogin()} disabled={props.busy}>{props.busy ? 'Verificando…' : 'Vincular navegador con passkey'}</button>}</details>{props.error && <p className="error-text">{props.error}</p>}</section></div>;
}

function Brand(){return <div className="brand auth-brand"><span className="brand-mark">R</span><div><h1>Ratchet</h1><small>Soporte seguro</small></div></div>;}
function Centered(props: { title: string; detail?: string; action?: () => void; actionLabel?: string }) { return <div className="auth-page"><section className="auth-card"><h1>{props.title}</h1>{props.detail && <p>{props.detail}</p>}{props.action && <button onClick={props.action}>{props.actionLabel || 'Reintentar'}</button>}</section></div>; }
function shortId(value: string): string { return value.slice(0, 8); }
function accountLabel(session: CurrentSessionResponse): string {
  if (session.role === 'CUSTOMER') return 'Cliente';
  if (session.staff_memberships.some((membership) => membership.staff_role === 'OWNER')) return 'Owner';
  return session.staff_memberships.some((membership) => membership.staff_role === 'ADMIN') ? 'Administrador' : 'Operador';
}
function connectivityLabel(state: ConnectivityState): string { return state === 'REALTIME' ? 'Conectado' : state === 'OFFLINE' ? 'Sin conexión' : 'Conectando'; }
function describeError(error: unknown): string { return friendlyError(error); }

function rememberedDeviceKey(loginName: string): string {
  return `auth-device:${loginName.trim().toLocaleLowerCase('en-US')}`;
}

async function loadRememberedDeviceId(db: IDBPDatabase<LocalDbSchema>, loginName: string): Promise<string | null> {
  const setting = await db.get('settings', rememberedDeviceKey(loginName));
  if (setting?.kind !== 'json' || typeof setting.value !== 'string') return null;
  return await db.get('device_identity', setting.value) ? setting.value : null;
}

async function rememberDeviceId(db: IDBPDatabase<LocalDbSchema>, loginName: string, deviceId: string): Promise<void> {
  await db.put('settings', {
    key: rememberedDeviceKey(loginName),
    kind: 'json',
    value: deviceId,
  } satisfies JsonSetting);
}

async function loadLocalDeviceCandidates(
  db: IDBPDatabase<LocalDbSchema>,
  rememberedDeviceId: string | null,
): Promise<string[]> {
  const guestDeviceIds = await loadGuestDeviceIds(db);
  return [...new Set([
    ...(rememberedDeviceId ? [rememberedDeviceId] : []),
    ...guestDeviceIds,
  ])];
}
