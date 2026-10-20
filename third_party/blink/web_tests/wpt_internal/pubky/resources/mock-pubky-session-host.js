import {PubkySessionHost, PubkySessionHostReceiver, PubkyStatus} from '/gen/third_party/blink/public/mojom/pubky/pubky.mojom.m.js';

export {PubkyStatus};

// Stands in for the browser side of navigator.pubky. Files live in a Map;
// `status` overrides the outcome of the next calls.
export class MockPubkySessionHost {
  constructor() {
    this.receiver_ = new PubkySessionHostReceiver(this);
    this.interceptor_ =
        new MojoInterfaceInterceptor(PubkySessionHost.$interfaceName);
    this.interceptor_.oninterfacerequest =
        e => this.receiver_.$.bindHandle(e.handle);
    this.interceptor_.start();
    this.reset();
  }

  reset() {
    this.status = PubkyStatus.kOk;
    this.publicKey = 'pubkyuserkey';
    this.files = new Map();
    this.requests = [];
  }

  stop() {
    this.receiver_.$.close();
    this.interceptor_.stop();
  }

  async requestSession(scopes) {
    this.requests.push({method: 'requestSession', scopes});
    return {
      status: this.status,
      publicKey: this.status === PubkyStatus.kOk ? this.publicKey : '',
    };
  }

  async get(path) {
    this.requests.push({method: 'get', path});
    const file = this.files.get(path);
    if (this.status !== PubkyStatus.kOk || !file) {
      const status =
          this.status !== PubkyStatus.kOk ? this.status : PubkyStatus.kNotFound;
      return {status, contentType: '', body: null};
    }
    return {
      status: PubkyStatus.kOk,
      contentType: file.contentType,
      body: {bytes: Array.from(file.bytes)},
    };
  }

  async put(path, body, contentType) {
    this.requests.push({method: 'put', path, contentType});
    if (this.status === PubkyStatus.kOk) {
      this.files.set(path, {bytes: new Uint8Array(body.bytes), contentType});
    }
    return {status: this.status};
  }

  async delete(path) {
    this.requests.push({method: 'delete', path});
    if (this.status === PubkyStatus.kOk) {
      this.files.delete(path);
    }
    return {status: this.status};
  }

  async list(path, options) {
    this.requests.push({method: 'list', path, options});
    if (this.status !== PubkyStatus.kOk) {
      return {status: this.status, entries: []};
    }
    const entries = [...this.files.keys()]
                        .filter(file => file.startsWith(path))
                        .sort()
                        .map(file => `pubky://${this.publicKey}${file}`);
    return {status: PubkyStatus.kOk, entries};
  }
}
