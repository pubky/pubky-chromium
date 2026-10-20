// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/pubky/pubky_session.h"

#include <optional>
#include <utility>

#include "mojo/public/cpp/base/big_buffer.h"
#include "third_party/blink/public/mojom/pubky/pubky.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_response_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_pubky_list_options.h"
#include "third_party/blink/renderer/core/fetch/body_stream_buffer.h"
#include "third_party/blink/renderer/core/fetch/form_data_bytes_consumer.h"
#include "third_party/blink/renderer/core/fetch/response.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/modules/pubky/pubky.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

using mojom::blink::PubkyStatus;

void OnGet(ScriptPromiseResolver<Response>* resolver,
           PubkyStatus status,
           const String& content_type,
           std::optional<mojo_base::BigBuffer> body) {
  if (status != PubkyStatus::kOk) {
    Pubky::Reject(resolver, status);
    return;
  }
  ScriptState* script_state = resolver->GetScriptState();
  if (!script_state->ContextIsValid()) {
    return;
  }
  ScriptState::Scope scope(script_state);
  DOMArrayBuffer* buffer = DOMArrayBuffer::Create(
      body ? base::span<const uint8_t>(*body) : base::span<const uint8_t>());
  BodyStreamBuffer* stream = BodyStreamBuffer::Create(
      script_state, MakeGarbageCollected<FormDataBytesConsumer>(buffer),
      /*signal=*/nullptr, /*cached_metadata_handler=*/nullptr);
  NonThrowableExceptionState exception_state;
  resolver->Resolve(Response::Create(script_state, stream, content_type,
                                     ResponseInit::Create(), exception_state));
}

void OnDone(ScriptPromiseResolver<IDLUndefined>* resolver, PubkyStatus status) {
  if (status != PubkyStatus::kOk) {
    Pubky::Reject(resolver, status);
    return;
  }
  resolver->Resolve();
}

void OnList(ScriptPromiseResolver<IDLSequence<IDLUSVString>>* resolver,
            PubkyStatus status,
            const Vector<String>& entries) {
  if (status != PubkyStatus::kOk) {
    Pubky::Reject(resolver, status);
    return;
  }
  resolver->Resolve(entries);
}

}  // namespace

PubkySession::PubkySession(Pubky* pubky, const String& public_key)
    : pubky_(pubky), public_key_(public_key) {}

PubkySession::~PubkySession() = default;

ScriptPromise<Response> PubkySession::get(ScriptState* script_state,
                                          const String& path,
                                          ExceptionState& exception_state) {
  mojom::blink::PubkySessionHost* host =
      pubky_->GetHost(script_state, exception_state);
  if (!host) {
    return EmptyPromise();
  }
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<Response>>(
      script_state, exception_state.GetContext());
  ScriptPromise<Response> promise = resolver->Promise();
  host->Get(path, BindOnce(&OnGet, WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLUndefined> PubkySession::put(ScriptState* script_state,
                                              const String& path,
                                              const V8BufferSource* body,
                                              const String& content_type,
                                              ExceptionState& exception_state) {
  mojom::blink::PubkySessionHost* host =
      pubky_->GetHost(script_state, exception_state);
  if (!host) {
    return EmptyPromise();
  }
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  ScriptPromise<IDLUndefined> promise = resolver->Promise();
  DOMArrayPiece bytes(body);
  host->Put(path, mojo_base::BigBuffer(bytes.ByteSpan()), content_type,
            BindOnce(&OnDone, WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLUndefined> PubkySession::Delete(
    ScriptState* script_state,
    const String& path,
    ExceptionState& exception_state) {
  mojom::blink::PubkySessionHost* host =
      pubky_->GetHost(script_state, exception_state);
  if (!host) {
    return EmptyPromise();
  }
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  ScriptPromise<IDLUndefined> promise = resolver->Promise();
  host->Delete(path, BindOnce(&OnDone, WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLSequence<IDLUSVString>> PubkySession::list(
    ScriptState* script_state,
    const String& path,
    const PubkyListOptions* options,
    ExceptionState& exception_state) {
  mojom::blink::PubkySessionHost* host =
      pubky_->GetHost(script_state, exception_state);
  if (!host) {
    return EmptyPromise();
  }
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<IDLUSVString>>>(
          script_state, exception_state.GetContext());
  ScriptPromise<IDLSequence<IDLUSVString>> promise = resolver->Promise();
  auto mojo_options = mojom::blink::PubkyListOptions::New();
  mojo_options->limit = options->hasLimit() ? options->limit() : 0;
  mojo_options->cursor = options->hasCursor() ? options->cursor() : g_empty_string;
  mojo_options->shallow = options->shallow();
  mojo_options->reverse = options->reverse();
  host->List(path, std::move(mojo_options),
             BindOnce(&OnList, WrapPersistent(resolver)));
  return promise;
}

void PubkySession::Trace(Visitor* visitor) const {
  visitor->Trace(pubky_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
