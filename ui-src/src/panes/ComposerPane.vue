<script setup lang="ts">
// A request written by hand: method, URL, headers, body.
//
// It is sent through the proxy rather than from the console, so the rules apply
// to it and it lands in the capture like any other request. That is the whole
// difference between this and a terminal: `curl` tells you what the origin
// answers, the Composer tells you what your *proxy* does with the request.

import CodeEditor from '../components/CodeEditor.vue';
import { newComposition, sendComposition, state } from '../store';

// The ones worth a click, in a datalist rather than a <select>: whistle's
// composer takes whatever method you give it (`getMethod` merely uppercases
// it), and a proxy is exactly where you go to try a verb nothing else sends.
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
</script>

<template>
  <section class="pane">
    <div class="compose">
      <div class="compose-line">
        <input
          v-model="state.compose.method"
          class="compose-method"
          list="composer-methods"
          spellcheck="false"
          aria-label="Method"
          placeholder="GET"
        />
        <datalist id="composer-methods">
          <option v-for="m in METHODS" :key="m" :value="m"></option>
        </datalist>
        <input
          v-model="state.compose.url"
          class="compose-url"
          spellcheck="false"
          aria-label="URL"
          placeholder="https://example.com/api/items"
          @keydown.enter="sendComposition()"
        />
      </div>

      <div class="compose-fields">
        <div class="compose-field">
          <label for="composer-headers">Headers</label>
          <textarea
            id="composer-headers"
            v-model="state.compose.headers"
            spellcheck="false"
            placeholder="Content-Type: application/json&#10;Authorization: Bearer …"
          ></textarea>
        </div>
        <div class="compose-field">
          <label>Body</label>
          <!-- The editor is the JSON one because bodies you retype by hand
               almost always are; nothing lints, so anything else is merely
               unhighlighted rather than wrong. -->
          <CodeEditor
            v-model="state.compose.body"
            language="json"
            placeholder='{ "name": "third" }'
            @save="sendComposition()"
          />
        </div>
      </div>

      <p class="hint">
        One <code>Name: value</code> per line. The request goes out through this proxy,
        so your rules apply to it and <code>from:composer</code> matches it.
        <code>⌘↩</code> sends.
      </p>
    </div>

    <div class="actions">
      <button class="btn primary" @click="sendComposition()">Send</button>
      <button class="btn" @click="newComposition()">New</button>
      <span class="spacer"></span>
      <span class="status">{{ state.composeStatus }}</span>
    </div>
  </section>
</template>
