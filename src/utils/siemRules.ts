/**
 * SIEM Rule Evaluation Utilities
 * Deterministic helpers for Rule 1: MULTIPLE FAILED LOGINS (RULE-001)
 */

export function isFailedLoginEvent(ev: any): boolean {
  if (!ev) return false;

  const eventType = String(ev.eventType || '').toUpperCase();
  const action = String(ev.normalizedData?.action || ev.action || '').toUpperCase();
  const reason = String(
    ev.normalizedData?.reason ||
    ev.normalizedData?.details?.reason ||
    ev.details?.reason ||
    ev.normalizedData?.failure_code ||
    ev.details?.failure_code ||
    ''
  ).toUpperCase();
  const detailsStr = typeof ev.normalizedData?.details === 'string'
    ? ev.normalizedData.details.toUpperCase()
    : typeof ev.details === 'string'
    ? ev.details.toUpperCase()
    : '';

  // 1. Standard event types
  if (
    eventType === 'FAILED_LOGIN' ||
    eventType === 'LOGIN_FAILED' ||
    eventType === 'AUTH_FAILURE' ||
    eventType === 'AUTHENTICATION_FAILURE'
  ) {
    return true;
  }

  // 2. Action flags
  if (
    action === 'AUTH_FAILED' ||
    action === 'LOGIN_FAILED' ||
    action === 'FAILED_LOGIN' ||
    action === 'AUTH_FAILURE' ||
    action === 'AUTHENTICATION_FAILURE' ||
    action.includes('AUTHENTICATION FAILURE') ||
    action.includes('AUTH_FAIL')
  ) {
    return true;
  }

  // 3. Reason / Details keywords
  if (
    reason.includes('USER_NOT_FOUND') ||
    reason.includes('BAD_PASSWORD') ||
    reason.includes('ERR_BAD_PASSWORD') ||
    reason.includes('AUTH_FAILED') ||
    detailsStr.includes('FAILED LOGIN') ||
    detailsStr.includes('AUTHENTICATION FAILURE')
  ) {
    return true;
  }

  return false;
}

/**
 * Deterministic helper for Rule 2: UNAUTHORIZED ACCESS (RULE-002)
 */
export function isUnauthorizedAccessEvent(ev: any): boolean {
  if (!ev) return false;

  const eventType = String(ev.eventType || '').toUpperCase();
  const action = String(ev.normalizedData?.action || ev.action || '').toUpperCase();
  const status = String(
    ev.normalizedData?.status ||
    ev.normalizedData?.statusCode ||
    ev.normalizedData?.details?.status ||
    ev.normalizedData?.details?.statusCode ||
    ev.details?.status ||
    ev.details?.statusCode ||
    ''
  ).toUpperCase();
  const reason = String(
    ev.normalizedData?.reason ||
    ev.normalizedData?.details?.reason ||
    ev.details?.reason ||
    ''
  ).toUpperCase();
  const detailsStr = typeof ev.normalizedData?.details === 'string'
    ? ev.normalizedData.details.toUpperCase()
    : typeof ev.details === 'string'
    ? ev.details.toUpperCase()
    : '';

  // 1. Event types
  if (
    eventType === 'UNAUTHORIZED_ACCESS' ||
    eventType === 'RBAC_VIOLATION' ||
    eventType === 'PERMISSION_DENIED' ||
    eventType === 'ACCESS_DENIED'
  ) {
    return true;
  }

  // 2. Actions
  if (
    action === 'ACCESS_DENIED' ||
    action === 'RBAC_VIOLATION' ||
    action === 'UNAUTHORIZED_ACCESS' ||
    action === 'FORBIDDEN_403' ||
    action === 'FORBIDDEN' ||
    action === 'PERMISSION_DENIED' ||
    action.includes('UNAUTHORIZED') ||
    action.includes('ACCESS_DENIED')
  ) {
    return true;
  }

  // 3. Status codes or ACL block flags
  if (
    status === '403' ||
    status === 'FORBIDDEN' ||
    status === 'FORBIDDEN_403' ||
    status === 'BLOCKED_BY_ACL'
  ) {
    return true;
  }

  // 4. Details / reason strings
  if (
    reason.includes('FORBIDDEN') ||
    reason.includes('UNAUTHORIZED') ||
    reason.includes('ACCESS DENIED') ||
    detailsStr.includes('FORBIDDEN') ||
    detailsStr.includes('UNAUTHORIZED') ||
    detailsStr.includes('BLOCKED_BY_ACL')
  ) {
    return true;
  }

  return false;
}
