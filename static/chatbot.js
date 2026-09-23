const chatToggle = document.getElementById("chatToggle");
const chatPanel = document.getElementById("chatPanel");
const chatClose = document.getElementById("chatClose");
const chatMessages = document.getElementById("chatMessages");
const chatInput = document.getElementById("chatInput");
const chatSend = document.getElementById("chatSend");

let chatHistory = [];

chatToggle.addEventListener("click", () => {
    chatPanel.style.display = chatPanel.style.display === "none" ? "flex" : "none";
});
chatClose.addEventListener("click", () => { chatPanel.style.display = "none"; });

function addMessage(text, sender) {
    const div = document.createElement("div");
    div.className = `chat-msg chat-${sender}`;
    div.textContent = text;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function sendMessage() {
    const text = chatInput.value.trim();
    if (!text) return;

    addMessage(text, "user");
    chatInput.value = "";
    chatInput.disabled = true;

    const typingEl = document.createElement("div");
    typingEl.className = "chat-msg chat-bot chat-typing";
    typingEl.textContent = "Thinking...";
    chatMessages.appendChild(typingEl);
    chatMessages.scrollTop = chatMessages.scrollHeight;

    fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text, history: chatHistory }),
    })
        .then(res => res.json())
        .then(data => {
            typingEl.remove();
            if (data.reply) {
                addMessage(data.reply, "bot");
                chatHistory.push({ role: "user", content: text });
                chatHistory.push({ role: "assistant", content: data.reply });
            } else {
                addMessage("Error: " + (data.error || "something went wrong"), "bot");
            }
            chatInput.disabled = false;
            chatInput.focus();
        })
        .catch(() => {
            typingEl.remove();
            addMessage("Connection error — please try again.", "bot");
            chatInput.disabled = false;
        });
}

chatSend.addEventListener("click", sendMessage);
chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage();
});