import { useSyncExternalStore } from 'react';

export type DeviceType = 'desktop' | 'android' | 'ios';

function detectDevice(): DeviceType {
  const ua = navigator.userAgent;

  // iPad with desktop-class browsing reports as Macintosh — treat as desktop (tablet)
  if (/iPad/i.test(ua)) return 'desktop';

  if (/iPhone|iPod/i.test(ua)) return 'ios';

  if (/Android/i.test(ua)) {
    // Android tablets typically have larger screens — treat as desktop
    if (window.matchMedia('(min-width: 768px)').matches) return 'desktop';
    return 'android';
  }

  return 'desktop';
}

let cached: DeviceType | null = null;

function getSnapshot(): DeviceType {
  if (cached === null) cached = detectDevice();
  return cached;
}

function getServerSnapshot(): DeviceType {
  return 'desktop';
}

function subscribe(_cb: () => void): () => void {
  // UA doesn't change at runtime — no subscription needed
  return () => {};
}

export function useDeviceType(): DeviceType {
  return useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}

export function isMobile(device: DeviceType): boolean {
  return device === 'android' || device === 'ios';
}
