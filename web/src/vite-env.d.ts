/// <reference types="vite/client" />
declare module "asciinema-player" {
  export function create(
    src: string | { data: string },
    elem: HTMLElement,
    opts?: Record<string, unknown>
  ): { dispose?: () => void };
}
