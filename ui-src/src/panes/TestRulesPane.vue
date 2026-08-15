<script setup lang="ts">
// Test Rules: which operators a request *would* hit, without making one.
//
// The same question `whistle-rs explain` answers on the command line, and the
// same one whistle's console answers in its own Test Rules dialog. It exists
// because a rule that never matches reports nothing — a working rule and a
// silently inert one look identical from the client side, and the only way to
// tell them apart is to ask the resolver directly.
//
// The rules under test are whatever is in the editor, not what the proxy is
// running: a rule is usually tested *before* it is saved.

import CodeEditor from '../components/CodeEditor.vue';
import { runTest, state, testCurrentRules } from '../store';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
</script>

<template>
  <section class="pane">
    <div class="compose">
      <div class="compose-line">
        <input
          v-model="state.test.method"
          class="compose-method"
          list="test-methods"
          spellcheck="false"
          aria-label="Method"
          placeholder="GET"
        />
        <datalist id="test-methods">
          <option v-for="m in METHODS" :key="m" :value="m"></option>
        </datalist>
        <input
          v-model="state.test.url"
          class="compose-url"
          spellcheck="false"
          aria-label="URL"
          placeholder="https://example.com/api/items"
          @keydown.enter="runTest()"
        />
        <input
          v-model="state.test.status"
          class="test-status"
          spellcheck="false"
          aria-label="Response status"
          placeholder="status"
          title="A response status turns this into a question about the response phase"
        />
      </div>

      <div class="compose-field">
        <label>Rules</label>
        <CodeEditor
          v-model="state.test.rules"
          language="whistle"
          placeholder="example.com  file://(hello)  includeFilter://m:GET"
          @save="runTest()"
        />
      </div>

      <div class="compose-fields">
        <div class="compose-field">
          <label for="test-headers">Headers</label>
          <textarea
            id="test-headers"
            v-model="state.test.headers"
            spellcheck="false"
            placeholder="Content-Type: application/json&#10;X-Env: staging"
          ></textarea>
        </div>
        <div class="compose-field">
          <label>Body</label>
          <CodeEditor
            v-model="state.test.body"
            language="json"
            placeholder='{ "type": "advanced" }'
            @save="runTest()"
          />
        </div>
      </div>

      <p class="hint">
        Nothing is sent anywhere. A status turns the question into one about the
        <em>response</em> phase, where a rule guarded by
        <code>includeFilter://s:404</code> finally has an answer. <code>⌘↩</code> tests.
      </p>

      <div v-if="state.testResult" class="test-result">
        <div class="test-url">{{ state.testResult.url }}</div>
        <table v-if="state.testResult.ops.length" class="test-ops">
          <thead>
            <tr><th>Operator</th><th>Value</th><th>Pattern</th></tr>
          </thead>
          <tbody>
            <tr v-for="(op, i) in state.testResult.ops" :key="i">
              <td>
                <code>{{ op.protocol }}</code>
                <span v-if="op.slot" class="tag" title="won the destination slot">slot</span>
                <span v-if="op.content" class="tag" title="the value is content, not a location">content</span>
              </td>
              <td><code class="val">{{ op.value }}</code></td>
              <td><code class="val">{{ op.pattern }}</code></td>
            </tr>
          </tbody>
        </table>
        <p v-else class="empty">No rule matched this request.</p>
      </div>
    </div>

    <div class="actions">
      <button class="btn primary" @click="runTest()">Test</button>
      <button class="btn" @click="testCurrentRules()">Load current rules</button>
      <span class="spacer"></span>
      <span class="status">{{ state.testStatus }}</span>
    </div>
  </section>
</template>

<style scoped>
.test-status {
  width: 6rem;
  flex: none;
}
.test-result {
  margin-top: 0.75rem;
  border-top: 1px solid var(--line);
  padding-top: 0.75rem;
  overflow: auto;
}
.test-url {
  font-family: var(--mono);
  font-size: 0.8rem;
  color: var(--muted);
  margin-bottom: 0.4rem;
}
.test-ops {
  border-collapse: collapse;
  width: 100%;
  font-size: 0.82rem;
}
.test-ops th {
  text-align: left;
  font-weight: 600;
  color: var(--muted);
  padding: 0.2rem 0.6rem 0.2rem 0;
}
.test-ops td {
  padding: 0.2rem 0.6rem 0.2rem 0;
  vertical-align: top;
}
.test-ops .val {
  word-break: break-all;
}
.tag {
  margin-left: 0.35rem;
  padding: 0 0.3rem;
  border-radius: 3px;
  background: var(--chip, rgba(127, 127, 127, 0.18));
  font-size: 0.7rem;
  color: var(--muted);
}
.empty {
  color: var(--muted);
}
</style>
