import { createApp } from 'vue';
import App from './App.vue';
import { initTheme } from './store';
import './styles/app.css';

// Before the first paint: the theme is a persisted choice, not a media query,
// and a console that flashes white on a dark desktop has already annoyed you.
initTheme();

createApp(App).mount('#app');
