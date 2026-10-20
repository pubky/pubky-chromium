// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/pubky/pubky.h"

#include "base/notreached.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/modules/pubky/pubky_session.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

// static
const char Pubky::kSupplementName[] = "Pubky";

// static
Pubky* Pubky::pubky(Navigator& navigator) {
  auto* supplement = Supplement<Navigator>::From<Pubky>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<Pubky>(navigator);
    ProvideTo(navigator, supplement);
  }
  return supplement;
}

Pubky::Pubky(Navigator& navigator)
    : Supplement<Navigator>(navigator), host_(navigator.DomWindow()) {}

Pubky::~Pubky() = default;

ScriptPromise<PubkySession> Pubky::requestSession(
    ScriptState* script_state,
    const Vector<String>& scopes,
    ExceptionState& exception_state) {
  mojom::blink::PubkySessionHost* host = GetHost(script_state, exception_state);
  if (!host) {
    return EmptyPromise();
  }
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<PubkySession>>(
      script_state, exception_state.GetContext());
  ScriptPromise<PubkySession> promise = resolver->Promise();
  host->RequestSession(scopes,
                       BindOnce(&Pubky::OnRequestSession, WrapPersistent(this),
                                WrapPersistent(resolver)));
  return promise;
}

mojom::blink::PubkySessionHost* Pubky::GetHost(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  // Use the navigator's own window: `script_state` may belong to another
  // frame that reached this navigator.
  LocalDOMWindow* window = GetSupplementable()->DomWindow();
  if (!script_state->ContextIsValid() || !window) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The document is not active.");
    return nullptr;
  }
  if (!host_.is_bound()) {
    window->GetBrowserInterfaceBroker().GetInterface(
        host_.BindNewPipeAndPassReceiver(
            window->GetTaskRunner(TaskType::kMiscPlatformAPI)));
  }
  return host_.get();
}

// static
void Pubky::Reject(ScriptPromiseResolverBase* resolver,
                   mojom::blink::PubkyStatus status) {
  switch (status) {
    case mojom::blink::PubkyStatus::kOk:
      NOTREACHED();
    case mojom::blink::PubkyStatus::kNotAllowed:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kNotAllowedError,
          "This site has no access to that Pubky path.");
      return;
    case mojom::blink::PubkyStatus::kNotFound:
      resolver->RejectWithDOMException(DOMExceptionCode::kNotFoundError,
                                       "No file at that Pubky path.");
      return;
    case mojom::blink::PubkyStatus::kInvalidArgument:
      resolver->RejectWithTypeError(
          "Pubky paths and scopes must be canonical, such as "
          "\"/pub/example.com/data.json\" or \"/pub/example.com/:rw\".");
      return;
    case mojom::blink::PubkyStatus::kNotSupported:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kNotSupportedError,
          "Encryption keys (the \"e\" action) are not supported.");
      return;
    case mojom::blink::PubkyStatus::kNotSignedIn:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kInvalidStateError,
          "The browser is not signed in to Pubky, or its approval expired.");
      return;
    case mojom::blink::PubkyStatus::kTooLarge:
      resolver->RejectWithDOMException(DOMExceptionCode::kQuotaExceededError,
                                       "The file is too large.");
      return;
    case mojom::blink::PubkyStatus::kNetworkError:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kNetworkError,
          "The Pubky homeserver could not be reached.");
      return;
  }
  NOTREACHED();
}

void Pubky::Trace(Visitor* visitor) const {
  visitor->Trace(host_);
  ScriptWrappable::Trace(visitor);
  Supplement<Navigator>::Trace(visitor);
}

void Pubky::OnRequestSession(ScriptPromiseResolver<PubkySession>* resolver,
                             mojom::blink::PubkyStatus status,
                             const String& public_key) {
  if (status != mojom::blink::PubkyStatus::kOk) {
    Reject(resolver, status);
    return;
  }
  resolver->Resolve(MakeGarbageCollected<PubkySession>(this, public_key));
}

}  // namespace blink
