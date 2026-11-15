export const MAX_USERNAME_LENGTH = 100;
export const MAX_PIN_LENGTH = 10;
export const MAX_PASSWORD_LENGTH = 100;

export function isBoolean(value: unknown): value is boolean {
  return typeof value === 'boolean';
}

export function isBoundedString(value: unknown, maxLength: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength;
}

export function isRequestBody(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
