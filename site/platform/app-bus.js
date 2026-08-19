(function(global){
'use strict';
const target=new EventTarget();
const sticky=new Map();
const on=(type,handler,{replay=false}={})=>{const wrapped=e=>handler(e.detail);target.addEventListener(type,wrapped);if(replay&&sticky.has(type))queueMicrotask(()=>handler(sticky.get(type)));return()=>target.removeEventListener(type,wrapped)};
const emit=(type,detail,{remember=false}={})=>{if(remember)sticky.set(type,detail);target.dispatchEvent(new CustomEvent(type,{detail}))};
const once=(type)=>new Promise(resolve=>{const off=on(type,d=>{off();resolve(d)})});
const state=(type)=>sticky.get(type);
global.DBMPlatform=global.DBMPlatform||{};
global.DBMPlatform.bus={on,emit,once,state};
})(window);
