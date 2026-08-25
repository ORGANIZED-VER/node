import sys, os
from pathlib import Path

content = open('viewer_app.py', 'r', encoding='utf-8').read()
content = content.replace('M-DIGGER PRO', 'Matrix_HQ')
content = content.replace('M-DIGGER', 'Matrix_HQ')
content = content.replace('MAILDIGGER', 'MATRIX_HQ')
content = content.replace('Mail Digger Pro', 'Matrix_HQ')
content = content.replace('logo.png', 'logo.jpg')

# Fix endpoint
old_ep = '''@app.get("/logo.jpg")\ndef get_logo(): \n    if os.path.exists('maildigger_logo_branded.png'): return FileResponse('maildigger_logo_branded.png')\n    return JSONResponse({"error": "not found"}, status_code=404)'''
new_ep = '''@app.get("/logo.jpg")\ndef get_logo(): \n    return FileResponse(Path(__file__).parent / 'logo.jpg')'''
content = content.replace(old_ep, new_ep)

# Add close button
sidebar_html = '''<div class="sidebar">
    <div class="logo-area">'''
new_sidebar_html = '''<div class="sidebar">
    <button onclick="document.querySelector('.sidebar').classList.remove('sidebar-open')" id="mobile-close-btn" style="display:none; position:absolute; top:12px; right:12px; background:transparent; border:none; color:#fff; font-size:1.5rem; cursor:pointer; z-index:1005;">✖</button>
    <div class="logo-area">'''
content = content.replace(sidebar_html, new_sidebar_html)

# Add CSS for mobile close button
css_search = '''#mobile-menu-toggle { display: block !important; }'''
css_replace = '''#mobile-menu-toggle { display: block !important; }
    #mobile-close-btn { display: block !important; }'''
content = content.replace(css_search, css_replace)

with open('viewer_app.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Done!')
