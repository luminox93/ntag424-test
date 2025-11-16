declare module 'node-aes-cmac' {
  function aesCmac(key: Buffer, message: Buffer): Buffer;
  export = aesCmac;
}
