import { createContext, useContext } from "react";

export const NotificationsContext = createContext({
    notifyError: (err) => console.error(err),
});

/**
 * @returns {{notifyError: (err: *, title?: string) => void}}
 */
export function useNotifications() {
    return useContext(NotificationsContext);
}
