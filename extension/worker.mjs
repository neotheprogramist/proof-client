// @ts-check
chrome.action.onClicked.addListener(async () => {
  try {
    await chrome.tabs.create({ url: chrome.runtime.getURL("index.html") });
  } catch (error) {
    console.error("Cannot open Proof Client", error);
  }
});
