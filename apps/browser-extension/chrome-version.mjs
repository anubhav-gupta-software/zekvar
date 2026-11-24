export function versionParts(version) {
  if (typeof version !== 'string' || !/^(?:0|[1-9]\d{0,4})(?:\.(?:0|[1-9]\d{0,4})){0,3}$/.test(version)) {
    throw new Error('Use a valid Chrome version.');
  }
  const parts = version.split('.').map(Number);
  if (parts.some((part) => part > 65535) || parts.every((part) => part === 0)) {
    throw new Error('Use a valid Chrome version.');
  }
  return parts;
}

export function newerVersion(next, previous) {
  const current = versionParts(next);
  const old = versionParts(previous);
  for (let index = 0; index < 4; index++) {
    const difference = (current[index] ?? 0) - (old[index] ?? 0);
    if (difference) return difference > 0;
  }
  return false;
}
