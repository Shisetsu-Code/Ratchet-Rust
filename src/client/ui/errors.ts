import { ApiError } from '../transport/api';
import { LocalStorageError } from '../storage/errors';

const MESSAGES: Readonly<Record<string, string>> = {
  AUTHENTICATION_FAILED: 'El usuario o la contraseña no son correctos.',
  SESSION_REQUIRED: 'Tu sesión terminó. Ingresá nuevamente.',
  SESSION_INVALID: 'Tu sesión terminó. Ingresá nuevamente.',
  SESSION_IDLE_EXPIRED: 'La sesión se cerró por inactividad. Ingresá nuevamente.',
  DEVICE_REVOKED: 'Este navegador fue desconectado de la cuenta. Ingresá nuevamente para volver a usarlo.',
  DEVICE_NOT_AVAILABLE: 'Este navegador ya no está habilitado. Ingresá nuevamente para registrarlo.',
  INVITATION_NOT_FOUND: 'El enlace de activación no es válido.',
  INVITATION_USED: 'Este enlace ya fue usado. Ingresá desde la página principal.',
  INVITATION_EXPIRED: 'Este enlace venció. Pedile al administrador uno nuevo.',
  REGISTRATION_CONFLICT: 'La cuenta ya fue activada. Ingresá desde la página principal.',
  LOGIN_NAME_TAKEN: 'Ese nombre de usuario ya existe. Elegí otro.',
  WORKSPACE_ADMIN_REQUIRED: 'Sólo el administrador del equipo puede administrar operadores.',
  REFERRAL_ISSUER_REQUIRED: 'Sólo un administrador o agente activo puede generar enlaces de captación.',
  WORKSPACE_STAFF_REQUIRED: 'Esta cuenta ya no pertenece al equipo.',
  OPERATOR_NOT_FOUND: 'El operador ya no existe o fue retirado.',
  ADMIN_SELF_REVOKE_FORBIDDEN: 'El administrador no puede desconectarse desde la lista de operadores.',
  OPERATOR_REQUIRED: 'Esta acción sólo puede aplicarse a una cuenta de operador.',
  AUTHENTICATOR_REAUTH_REQUIRED: 'Confirmá nuevamente tu contraseña para continuar.',
  FORBIDDEN: 'No tenés permiso para realizar esta acción.',
  ORIGIN_MISMATCH: 'La solicitud fue rechazada por seguridad. Recargá la página e intentá nuevamente.',
  VALIDATION_ERROR: 'Revisá los datos ingresados e intentá nuevamente.',
  CHAT_STORAGE_QUOTA_EXCEEDED: 'Este chat alcanzó su límite de almacenamiento. Contactá al administrador antes de enviar más mensajes.',
  ATTACHMENT_QUOTA_EXCEEDED: 'Se alcanzó el límite de almacenamiento de adjuntos. Contactá al administrador o enviá el mensaje sin el archivo.',
  WALLPAPER_QUOTA_EXCEEDED: 'Se alcanzó el límite de almacenamiento de fondos. Elegí un fondo predeterminado o contactá al administrador.',
  STORAGE_RECONCILIATION_PENDING: 'El servidor está actualizando el almacenamiento del chat. Esperá un momento e intentá nuevamente.',
};

export function friendlyError(error: unknown): string {
  if (error instanceof ApiError) return MESSAGES[error.type] ?? 'No se pudo completar la operación. Intentá nuevamente.';
  if (error instanceof LocalStorageError) {
    if (/independent identity root|Multiple legacy identity roots|signer is revoked or absent|identity.*changed/i.test(error.message)) {
      return 'No se pudo validar la sesión del navegador. Volvé a ingresar y reintentá.';
    }
    if (error.type === 'QUOTA_EXCEEDED') return 'El navegador no tiene espacio suficiente para guardar el chat.';
    if (error.type === 'LOCK_TIMEOUT' || error.type === 'LEASE_LOST' || error.type === 'STATE_VERSION_CONFLICT') {
      return 'El chat se está actualizando. Esperá un momento e intentá nuevamente.';
    }
    return 'No se pudo actualizar el chat de forma segura. Recargá la página e intentá nuevamente.';
  }
  if (error instanceof DOMException && error.name === 'TimeoutError') return 'El servidor tardó demasiado en responder. Intentá nuevamente.';
  if (error instanceof TypeError) return 'No se pudo conectar con el servidor. Revisá tu conexión e intentá nuevamente.';
  return error instanceof Error ? error.message : 'Ocurrió un error inesperado. Intentá nuevamente.';
}
