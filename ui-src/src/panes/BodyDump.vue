<script setup lang="ts">
// A captured body, as text, as bytes, or as the image it is.
//
// The text view is the one that was always here: re-indented when the body is
// JSON, left alone when it is not. The other two exist because a body the proxy
// judged non-textual used to arrive as the sentence `[binary, N bytes]` and
// nothing else — the bytes were dropped as the session was serialized. They now
// come from `/body.bin`, fetched only when a body is opened as bytes.

import { computed, onBeforeUnmount, ref, watch } from 'vue';
import type { BodyBytes, BodyCapture } from '../api';
import { api } from '../api';
import { fmtBytes, prettyJson } from '../format';
import { state } from '../store';

const props = defineProps<{
  body: BodyCapture | undefined;
  /** The session the body belongs to, so its bytes can be asked for. */
  session: number;
  side: 'req' | 'res';
}>();

type View = 'text' | 'hex' | 'image';

const view = ref<View>('text');
const bytes = ref<BodyBytes | null>(null);
const loading = ref(false);
const failed = ref(false);
/** Held so it can be revoked: an object URL outlives its blob until it is. */
const imageUrl = ref('');

const isImage = computed(() => !!bytes.value?.type.startsWith('image/'));

/**
 * What the header line says, which is the one place truncation is stated in
 * bytes. A capped preview is a prefix of the body and nothing in the bytes
 * themselves can say so.
 */
const note = computed(() => {
  const b = props.body;
  if (!b) return '';
  if (!b.truncated) return `${b.len} bytes`;
  if (b.undecodable) {
    return `${b.len} bytes — its content-encoding would not decode; this is what came out before it broke`;
  }
  return `${fmtBytes(bytes.value?.bytes.length)} of ${b.len} bytes — the rest was not captured`;
});

/** Non-null exactly when the body is JSON, which is when the toggle appears. */
const formatted = computed(() => prettyJson(shownText.value));

/**
 * The body as text. For a body the proxy called binary that is the *fetched*
 * bytes decoded, not its `[binary, N bytes]` marker: a content type is a claim,
 * and `application/octet-stream` over a JSON payload is an ordinary mistake to
 * want to see through.
 */
const shownText = computed(() => {
  if (props.body?.binary) {
    return bytes.value ? new TextDecoder().decode(bytes.value.bytes) : '';
  }
  return props.body?.text ?? '';
});

const shown = computed(() =>
  state.prettyBody && formatted.value !== null ? formatted.value : shownText.value,
);

const HEX = '0123456789abcdef';

/** `00000010  89 50 4e 47 …  |.PNG…|`, sixteen bytes to the line. */
const hexDump = computed(() => {
  const data = bytes.value?.bytes;
  if (!data) return '';
  const lines: string[] = [];
  for (let at = 0; at < data.length; at += 16) {
    const row = data.subarray(at, at + 16);
    let hex = '';
    let ascii = '';
    for (let i = 0; i < 16; i++) {
      const b = row[i];
      hex += i < row.length ? HEX[b >> 4] + HEX[b & 15] + ' ' : '   ';
      if (i === 7) hex += ' ';
      // Only printable ASCII reads as itself; everything else is a dot, so the
      // column stays one character per byte and lines up with the hex.
      if (i < row.length) ascii += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.';
    }
    lines.push(`${at.toString(16).padStart(8, '0')}  ${hex} |${ascii}|`);
  }
  return lines.join('\n');
});

async function load(): Promise<BodyBytes | null> {
  if (bytes.value) return bytes.value;
  loading.value = true;
  failed.value = false;
  try {
    const got = await api.bodyBytes(props.session, props.side);
    bytes.value = got;
    return got;
  } catch {
    failed.value = true;
    return null;
  } finally {
    loading.value = false;
  }
}

async function show(next: View): Promise<void> {
  if (next !== 'text' || props.body?.binary) await load();
  if (next === 'image' && bytes.value && !imageUrl.value) {
    imageUrl.value = URL.createObjectURL(
      new Blob([bytes.value.bytes as BlobPart], { type: bytes.value.type }),
    );
  }
  view.value = next;
}

/**
 * Save the bytes as a file, from the blob already in hand rather than by
 * navigating to `/body.bin` — the proxy serves that route as an attachment for
 * safety, but a navigation would still leave the console's page to do it.
 */
async function saveBody(): Promise<void> {
  const got = await load();
  if (!got) return;
  const url = URL.createObjectURL(new Blob([got.bytes as BlobPart], { type: got.type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = got.filename;
  a.click();
  URL.revokeObjectURL(url);
}

function forget(): void {
  if (imageUrl.value) URL.revokeObjectURL(imageUrl.value);
  imageUrl.value = '';
  bytes.value = null;
  failed.value = false;
}

// A different body is a different fetch. A binary one is opened as bytes
// straight away: its text view holds a marker until they arrive, so waiting for
// a click would only show the marker first.
watch(
  () => [props.session, props.side, props.body?.len],
  async () => {
    forget();
    view.value = 'text';
    if (!props.body?.len || !props.body.binary) return;
    const got = await load();
    await show(got?.type.startsWith('image/') ? 'image' : 'hex');
  },
  { immediate: true },
);

onBeforeUnmount(forget);
</script>

<template>
  <div v-if="!body || !body.len" class="empty">no body captured</div>
  <template v-else>
    <p class="hint bodybar">
      <span :class="{ warn: body.truncated }">{{ note }}</span>
      <button
        v-if="view === 'text' && formatted !== null"
        class="btn tiny"
        @click="state.prettyBody = !state.prettyBody"
      >
        {{ state.prettyBody ? 'Raw' : 'Format JSON' }}
      </button>
      <span class="spacer"></span>
      <span class="viewsel">
        <button :aria-selected="view === 'text'" @click="show('text')">Text</button>
        <button :aria-selected="view === 'hex'" @click="show('hex')">Hex</button>
        <button v-if="isImage" :aria-selected="view === 'image'" @click="show('image')">
          Image
        </button>
      </span>
      <button class="btn tiny" :disabled="loading" @click="saveBody()">
        {{ body.truncated ? 'Download preview' : 'Download' }}
      </button>
    </p>

    <p v-if="failed" class="empty">the proxy would not hand over the bytes</p>
    <p v-else-if="loading && !bytes" class="empty">reading the captured bytes…</p>
    <div v-else-if="view === 'image'" class="img-preview">
      <img :src="imageUrl" :alt="`${bytes?.type} response body`" />
    </div>
    <pre v-else-if="view === 'hex'" class="dump hex">{{ hexDump }}</pre>
    <pre v-else class="dump">{{ shown }}</pre>
  </template>
</template>
