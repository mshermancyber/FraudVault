import { createContext, useContext } from 'react';
import { useDeviceType, type DeviceType } from '@/hooks/useDeviceType';

const DeviceContext = createContext<DeviceType>('desktop');

export function DeviceProvider({ children }: { children: React.ReactNode }) {
  const device = useDeviceType();
  return (
    <DeviceContext.Provider value={device}>{children}</DeviceContext.Provider>
  );
}

export function useDevice(): DeviceType {
  return useContext(DeviceContext);
}
