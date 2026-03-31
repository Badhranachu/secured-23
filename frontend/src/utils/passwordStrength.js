const commonPasswordParts = [
  'password',
  'admin',
  'welcome',
  'qwerty',
  'letmein',
  'changeme',
  'default',
  'secret',
  'test',
  'demo',
  'root',
  '123456',
  'password123',
];

const sequentialPatterns = [
  '0123456789',
  '1234567890',
  'abcdefghijklmnopqrstuvwxyz',
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm',
];

function normalizeTokens(values = []) {
  return values
    .map((value) => String(value || '').toLowerCase().replace(/[^a-z0-9]/g, ''))
    .filter((value) => value.length >= 3);
}

export function evaluatePasswordStrength(password, relatedValues = []) {
  const value = password || '';
  if (!value) {
    return {
      present: false,
      score: 0,
      max_score: 6,
      level: 'not_available',
      label: 'Not available',
      summary: 'No password entered yet.',
      suggestions: ['Enter a password to see strength guidance.'],
    };
  }

  const lowered = value.toLowerCase();
  const compact = lowered.replace(/[^a-z0-9]/g, '');
  const relatedTokens = normalizeTokens(relatedValues);
  const hasLower = /[a-z]/.test(value);
  const hasUpper = /[A-Z]/.test(value);
  const hasDigit = /\d/.test(value);
  const hasSymbol = /[^A-Za-z0-9]/.test(value);
  const hasCommonPattern = commonPasswordParts.some((part) => lowered.includes(part));
  const hasRepetition = /(.){2,}/.test(value);
  const hasSequence = sequentialPatterns.some((pattern) => compact.includes(pattern));
  const matchesContext = relatedTokens.some((token) => compact.includes(token));

  let score = 0;
  if (value.length >= 8) score += 1;
  if (value.length >= 12) score += 1;

  const variety = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
  if (variety >= 2) score += 1;
  if (variety >= 3) score += 1;
  if (variety === 4) score += 1;
  if (value.length >= 16 && !(hasCommonPattern || hasRepetition || hasSequence || matchesContext)) score += 1;

  const penalties = [hasCommonPattern, hasRepetition, hasSequence, matchesContext].filter(Boolean).length;
  score = Math.max(0, Math.min(6, score - penalties));

  let level = 'weak';
  let label = 'Weak';
  if (score <= 1) {
    level = 'weak';
    label = 'Weak';
  } else if (score <= 3) {
    level = 'fair';
    label = 'Fair';
  } else if (score <= 4) {
    level = 'good';
    label = 'Good';
  } else {
    level = 'strong';
    label = 'Strong';
  }

  const suggestions = [];
  if (value.length < 12) suggestions.push('Use at least 12 characters.');
  if (!hasUpper) suggestions.push('Add an uppercase letter.');
  if (!hasLower) suggestions.push('Add a lowercase letter.');
  if (!hasDigit) suggestions.push('Add a number.');
  if (!hasSymbol) suggestions.push('Add a special character.');
  if (hasCommonPattern) suggestions.push('Avoid common words like password, admin, or test.');
  if (hasRepetition) suggestions.push('Avoid repeated characters.');
  if (hasSequence) suggestions.push('Avoid sequences like 123456 or qwerty.');
  if (matchesContext) suggestions.push('Do not include project, domain, email, or server names.');
  if (!suggestions.length) suggestions.push('Looks strong. Keep it unique and rotate it if shared.');

  const summary = {
    weak: 'Easy to guess. Change this before relying on it.',
    fair: 'Acceptable for short-term testing, but stronger is better.',
    good: 'Reasonably strong. A longer passphrase would be even better.',
    strong: 'Strong password with healthy complexity.',
  }[level];

  return {
    present: true,
    score,
    max_score: 6,
    level,
    label,
    summary,
    suggestions,
  };
}

export function passwordTone(level) {
  if (level === 'strong' || level === 'good') return 'success';
  if (level === 'fair') return 'warning';
  if (level === 'weak') return 'danger';
  return 'neutral';
}
