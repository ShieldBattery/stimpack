// This implementation is based on type-fest's Opaque, just want to avoid needing the dep
declare const tag: unique symbol
declare type Tagged<Token> = {
  readonly [tag]: Token
}
export type StimpackProcess = Tagged<'StimpackProcess'>

/** Arguments that control the launch/injection process. */
export interface LaunchArgs {
  /** A path to the executable to launch. */
  appPath: string
  /** The command-line arguments to pass to the executable. */
  args: string
  /** The "current directory" the application will be started with. */
  currentDir: string
  /** A path to the DLL to inject into the process. */
  dllPath: string
  /** The name of a function exported by the DLL to call after injection. */
  dllFunc: string
  /** A function that will be called when the injector needs to log information. */
  logCallback: (message: string) => void
}

/**
 * Launches a process, injects a DLL, and calls the specified function in the DLL.
 *
 * @returns A promise that resolves with the process object if successful, or rejects with an error
 *  otherwise.
 */
export function launch(args: LaunchArgs): Promise<StimpackProcess>

/**
 * Waits for the given process to exit.
 *
 * @returns A promise that resolves with the process exit code if successful, or rejects if an error
 *  occurs while waiting for it to exit.
 */
export function waitForExit(process: StimpackProcess): Promise<number>
