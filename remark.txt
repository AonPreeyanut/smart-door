# SMART DOOR ACCESS SYSTEM - SETUP GUIDE

## 📌 1. REQUIREMENTS (สิ่งที่ต้องติดตั้งก่อน)

* Python 3.10 หรือใหม่กว่า
* pip (มากับ Python)
* Internet (สำหรับโหลด package)

## 📌 2. ติดตั้ง Library ที่จำเป็น

เปิด Command Prompt / Terminal แล้วรัน:

pip install flask
pip install flask_sqlalchemy
pip install werkzeug

## 📌 3. โครงสร้างโปรเจค

ต้องมีไฟล์ประมาณนี้:

project/
│
├── app.py
├── database.db (จะถูกสร้างอัตโนมัติ)
│
└── templates/
├── login.html
├── dashboard.html
├── otp.html
├── request_otp.html
├── logs.html
└── admin.html

## 📌 4. วิธีรันโปรเจค

ไปที่โฟลเดอร์โปรเจค แล้วรัน:

python app.py

ถ้าสำเร็จ จะขึ้นประมาณนี้:
Running on http://127.0.0.1:5000

## 📌 5. เข้าใช้งานระบบ

เปิด Browser แล้วไปที่:

http://127.0.0.1:5000

Login:
username: admin
password: 1234

## 📌 6. ฟีเจอร์ในระบบ

* Login / Logout
* Door Control (Open / Lock)
* OTP (Mobile request + Web enter)
* Access Logs
* Admin Panel (เพิ่ม / ลบ user)
* Realtime / Manual Log Refresh

## 📌 7. ทดสอบผ่านมือถือ (Optional)

ติดตั้ง ngrok แล้วรัน:

ngrok http 5000

จะได้ URL เช่น:
https://xxxx.ngrok-free.dev

นำไปเปิดในมือถือได้เลย

## 📌 8. หมายเหตุ

* database.db จะถูกสร้างอัตโนมัติครั้งแรก
* หากต้องการ reset ระบบ → ลบไฟล์ database.db แล้วรันใหม่
* OTP จะเปลี่ยนทุก 20 วินาที
* ต้องเปิด server ค้างไว้ตลอดการใช้งาน

## 📌 9. ปัญหาที่พบบ่อย

❌ Module not found
→ แก้: pip install ใหม่อีกครั้ง

❌ Port 5000 ถูกใช้งาน
→ แก้: เปลี่ยน port ใน app.py เช่น:
app.run(debug=True, port=5001)

❌ เปิดมือถือไม่ได้
→ แก้: ใช้ ngrok หรือเช็ค firewall

======================================
END OF FILE
===========
