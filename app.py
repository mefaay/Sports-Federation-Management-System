import logging
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, jsonify
)
from models import (
    db, Kullanici, Rol, Kulup, Brans,
    YasKategorisi, Sporcu, Antrenor, IlTemsilcisi,
    Hakem, Musabaka, musabaka_hakem, Yonetici, Duyuru, Katilimci,
    HakemBelge, HakemBasvuru, HakemBelgeBasvuru,
    SporDali, SonucTuru, SporDaliSonuc, BelgeTipi,
    OnlineKullanici, OturumAcmaYetkisiOlmayan,
    KullaniciGecmis, HakemGorevlendirmeTalebi, GorevlendirmeDurumu
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect, generate_csrf
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import joinedload
from datetime import date
from functools import wraps
from collections import defaultdict
from io import BytesIO
from sqlalchemy import func
from pandas import ExcelWriter
import pandas as pd
from models import convert_utc_to_local
from sqlalchemy.exc import IntegrityError
import xlsxwriter
from flask import current_app
from models import SifreSifirlamaToken
import os
import re
import shutil
import itertools
import requests
import secrets
from math import ceil


app = Flask(__name__)


# Özel loglama filtresi
class IgnoreStaticFilter(logging.Filter):
    def filter(self, record):
        # Filtrelemek istediğiniz uzantılar ve mesaj içerikleri
        extensions = ["/static/", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico"]
        ignored_messages = ["Bad request version"]

        message = record.getMessage()
        if any(ext in message for ext in extensions):
            return False
        if any(ignored_message in message for ignored_message in ignored_messages):
            return False
        return True


# Werkzeug loglarını filtrele
log = logging.getLogger('werkzeug')
log.setLevel(logging.INFO)
log.addFilter(IgnoreStaticFilter())


# Fotoğraf yükleme için ayarlar
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'gif'}

# Belge yükleme için ayarlar
app.config['BELGE_UPLOAD_FOLDER'] = 'static/hakembelge'
app.config['BELGE_ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx'}

app.config['HAKEM_ADAY_UPLOAD_FOLDER'] = 'static/adayhakem'
app.config['HAKEM_ADAY_ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx'}


def allowed_file(filename, file_type='image'):
    if file_type == 'image':
        allowed_extensions = app.config['ALLOWED_EXTENSIONS']
    elif file_type == 'document':
        allowed_extensions = app.config['BELGE_ALLOWED_EXTENSIONS']
    else:
        return False

    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


# Uygulamanın konfigürasyonlarını ayarla
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///spor_veritabani.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'gizli_bir_anahtar'
app.config['WTF_CSRF_ENABLED'] = False
app.config['BASVURULAR_ACIK'] = False  # Varsayılan olarak başvurular açık


# CSRF korumasını uygulamayla ilişkilendir
csrf = CSRFProtect(app)

# SQLAlchemy nesnesini uygulamayla ilişkilendir
db.init_app(app)


@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bu sayfayı görüntülemek için oturum açmalısınız.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def check_permission(*required_roles):
    def decorator(inner_func):
        @wraps(inner_func)
        def wrapper(*args, **kwargs):
            role = session.get('role')
            if role in required_roles:
                return inner_func(*args, **kwargs)
            else:
                flash('Bu işlemi yapma yetkiniz yok.', 'danger')
                return redirect(url_for('dashboard'))

        return wrapper

    return decorator


# Uygulamanın URL yönlendirmelerini tanımla
@app.route('/')
def home():
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = Kullanici.query.filter_by(kullanici_adi=username).first()
        if user and check_password_hash(user.sifre, password):
            if not user.aktif:
                flash('Bu hesap pasifleştirilmiş. Lütfen yönetici ile iletişime geçiniz.', 'danger')
                return redirect(url_for('login'))

            session['user_id'] = user.id
            session['role'] = user.rol.name

            # Kullanıcının ilişkili olduğu rollerin ID'lerini oturuma sakla
            if user.rol.name == 'Kulup':
                kulup = Kulup.query.filter_by(kullanici_id=user.id).first()
                if kulup:
                    session['kulup_id'] = kulup.id
            elif user.rol.name == 'Antrenor':
                antrenor = Antrenor.query.filter_by(kullanici_id=user.id).first()
                if antrenor:
                    session['antrenor_id'] = antrenor.id
            elif user.rol.name == 'Hakem':
                hakem = Hakem.query.filter_by(kullanici_id=user.id).first()
                if hakem:
                    session['hakem_id'] = hakem.id
            elif user.rol.name == 'IlTemsilcisi':
                il_temsilcisi = IlTemsilcisi.query.filter_by(kullanici_id=user.id).first()
                if il_temsilcisi:
                    session['il_temsilcisi_id'] = il_temsilcisi.id
                    session['il_temsilcisi_il'] = il_temsilcisi.il

            # OnlineKullanici tablosunda mevcut bir kayıt olup olmadığını kontrol et
            now = datetime.now(timezone.utc)
            ip_adresi = request.remote_addr
            online_kullanici = OnlineKullanici.query.filter_by(kullanici_id=user.id).first()
            if online_kullanici:
                # Mevcut kaydı güncelle
                online_kullanici.son_aktif_zaman = now
                online_kullanici.son_url = '/dashboard'
            else:
                # Yeni kayıt ekle
                online_kullanici = OnlineKullanici(kullanici_id=user.id, son_aktif_zaman=now, son_url='/dashboard')
                db.session.add(online_kullanici)

            # Aynı IP adresine sahip oturum açmamış kullanıcı kaydını sil
            oturum_acmamiss_kullanici = OturumAcmaYetkisiOlmayan.query.filter_by(ip_adresi=ip_adresi).first()
            if oturum_acmamiss_kullanici:
                db.session.delete(oturum_acmamiss_kullanici)

            db.session.commit()

            app.logger.info(f"Kullanıcı giriş yaptı. Kullanıcı ID: {user.id}, Rol: {user.rol.name}")
            return redirect(url_for('dashboard'))
        else:
            flash('Geçersiz Kullanıcı Adı veya Şifre!')

    return render_template('login.html')


def is_mhk_member(user_id):
    hakem = Hakem.query.filter_by(kullanici_id=user_id).first()
    return hakem.mhk_uyesi_mi if hakem else False


@app.context_processor
def utility_processor():
    return {'is_mhk_member': is_mhk_member}


def not_yetkili_kullanici(hakem_id):
    kullanici_id = session.get('user_id')
    if session.get('role') == 'Yonetici' or is_mhk_member(kullanici_id):
        return False
    kullanici_hakem = Hakem.query.filter_by(kullanici_id=kullanici_id).first()
    if kullanici_hakem and kullanici_hakem.id == hakem_id:
        return False
    return True


@app.before_request
def before_request():
    user_id = session.get('user_id')
    current_url = request.path
    now = datetime.now(timezone.utc)
    ip_adresi = request.remote_addr

    if user_id:
        kullanici = db.session.get(Kullanici, user_id)
        kullanici_adi = kullanici.kullanici_adi
        kullanici_rol = kullanici.rol.name

        online_kullanici = OnlineKullanici.query.filter_by(kullanici_id=user_id).first()
        if online_kullanici:
            online_kullanici.son_aktif_zaman = now
            online_kullanici.son_url = current_url
        else:
            online_kullanici = OnlineKullanici(kullanici_id=user_id, son_aktif_zaman=now, son_url=current_url)
            db.session.add(online_kullanici)

        if not current_url.startswith('/static'):
            kullanici_gecmis = KullaniciGecmis(kullanici_id=user_id, url=current_url, zaman=now, ip_adresi=ip_adresi)
            db.session.add(kullanici_gecmis)

        try:
            db.session.commit()
            if not current_url.startswith(('/static', '/favicon.ico')):
                app.logger.info(
                    f"Kullanıcı durumu güncellendi. "
                    f"Kullanıcı Adı: {kullanici_adi}, Rol: {kullanici_rol}, "
                    f"Son Aktif Zaman: {now}, Son URL: {current_url}"
                )
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Veritabanı hatası: {str(e)}")
    else:
        if not current_url.startswith('/static'):
            oturum_acmamiss_kullanici = OturumAcmaYetkisiOlmayan.query.filter_by(ip_adresi=ip_adresi).first()
            if oturum_acmamiss_kullanici:
                oturum_acmamiss_kullanici.url = current_url
                oturum_acmamiss_kullanici.zaman = now
            else:
                oturum_acmamiss_kullanici = OturumAcmaYetkisiOlmayan(ip_adresi=ip_adresi, url=current_url, zaman=now)
                db.session.add(oturum_acmamiss_kullanici)
            db.session.commit()
            app.logger.info(f"Oturum açmamış kullanıcı. IP Adresi: {ip_adresi}, URL: {current_url}")


@app.route('/online-kullanicilar')
@login_required
@check_permission('Yonetici')
def online_kullanicilar():
    online_kullanicilar_list = OnlineKullanici.query.options(
        joinedload(OnlineKullanici.kullanici)
    ).order_by(OnlineKullanici.son_aktif_zaman.desc()).all()

    oturum_acmamiss_kullanicilar_list = OturumAcmaYetkisiOlmayan.query.order_by(
        OturumAcmaYetkisiOlmayan.zaman.desc()
    ).all()

    return render_template(
        'online_kullanicilar.html',
        online_kullanicilar=online_kullanicilar_list,
        oturum_acmamiss_kullanicilar=oturum_acmamiss_kullanicilar_list
    )


@app.route('/temizle_gecmis', methods=['POST'])
@login_required
@check_permission('Yonetici')
def temizle_gecmis():
    try:
        db.session.query(OnlineKullanici).delete()
        db.session.commit()
        flash('Online kullanıcı geçmişi başarıyla temizlendi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Geçmiş temizlenirken bir hata oluştu: {str(e)}', 'danger')
    return redirect(url_for('online_kullanicilar'))


@app.route('/kullanici-gecmis/<int:kullanici_id>')
@login_required
@check_permission('Yonetici')  # Bu sayfayı sadece yönetici kullanıcılar görebilir
def kullanici_gecmis_view(kullanici_id):  # Adı benzersiz hale getirin
    gecmis = KullaniciGecmis.query.filter_by(kullanici_id=kullanici_id).order_by(KullaniciGecmis.zaman.desc()).all()
    kullanici = db.session.get(Kullanici, kullanici_id)
    return render_template('kullanici_gecmis.html', gecmis=gecmis, kullanici=kullanici)


@app.route('/kullanici-gecmis/temizle/<int:kullanici_id>', methods=['POST'])
@login_required
@check_permission('Yonetici')  # Bu işlemi sadece yönetici kullanıcılar yapabilir
def kullanici_gecmis_temizle_view(kullanici_id):  # Adı benzersiz hale getirin
    KullaniciGecmis.query.filter_by(kullanici_id=kullanici_id).delete()
    db.session.commit()
    flash('Kullanıcı geçmişi başarıyla temizlendi.', 'success')
    return redirect(url_for('kullanici_gecmis_view', kullanici_id=kullanici_id))


@app.route('/oturum-acmamiss-gecmis/<ip_adresi>')
@login_required
@check_permission('Yonetici')
def oturum_acmamiss_gecmis_view(ip_adresi):
    gecmis = OturumAcmaYetkisiOlmayan.query.filter_by(ip_adresi=ip_adresi).order_by(
        OturumAcmaYetkisiOlmayan.zaman.desc()
    ).all()
    return render_template(
        'oturum_acmamiss_gecmis.html',
        gecmis=gecmis,
        ip_adresi=ip_adresi
    )


@app.route('/temizle_oturum_acmamiss_gecmis/<ip_adresi>', methods=['POST'])
@login_required
@check_permission('Yonetici')
def temizle_oturum_acmamiss_gecmis(ip_adresi):
    try:
        OturumAcmaYetkisiOlmayan.query.filter_by(ip_adresi=ip_adresi).delete()
        db.session.commit()
        flash('Oturum açmamış kullanıcı geçmişi başarıyla temizlendi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Geçmiş temizlenirken bir hata oluştu: {str(e)}', 'danger')
    return redirect(url_for('online_kullanicilar'))


@app.route('/temizle_oturum_acmamiss_toplu', methods=['POST'])
@login_required
@check_permission('Yonetici')
def temizle_oturum_acmamiss_toplu():
    oturum_acmamiss_ids = request.form.getlist('oturum_acmamiss_ids')
    for id in oturum_acmamiss_ids:
        kayit = OturumAcmaYetkisiOlmayan.query.get(id)
        if kayit:
            db.session.delete(kayit)
    db.session.commit()
    flash('Seçili oturum açmamış kullanıcılar başarıyla silindi.', 'success')
    return redirect(url_for('online_kullanicilar'))


@app.route('/logout')
def logout():
    user_id = session.get('user_id')

    # Örneğin, loglama için user_id'yi kullanabilirsiniz
    current_app.logger.info(f'User {user_id} logged out.')

    session.pop('user_id', None)
    session.pop('role', None)
    flash('Başarıyla çıkış yaptınız.')
    return redirect(url_for('home'))


@app.template_filter('kisalt')
def kisalt_filter(kulup_adi):
    return kulup_adi.replace("SPOR KULÜBÜ", "S.K.")


@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')

    if role == 'Yonetici':
        # Verileri hesaplayın
        kulup_sayisi = Kulup.query.count()
        antrenor_sayisi = Antrenor.query.count()
        sporcu_sayisi = Sporcu.query.count()
        hakem_sayisi = Hakem.query.count()
        kullanici_sayisi = Kullanici.query.count()
        musabaka_sayisi = Musabaka.query.count()

        son_kulupler = Kulup.query.order_by(Kulup.id.desc()).limit(2).all()
        son_antrenorler = Antrenor.query.order_by(Antrenor.id.desc()).limit(2).all()
        son_sporcular = Sporcu.query.order_by(Sporcu.id.desc()).limit(2).all()
        son_hakemler = Hakem.query.order_by(Hakem.id.desc()).limit(2).all()
        son_kullanicilar = Kullanici.query.order_by(Kullanici.id.desc()).limit(2).all()

        # Yaklaşan Müsabakalar: Bugünden itibaren sonraki 2 ay içinde başlayacak müsabakalar
        today = datetime.today()
        two_months_later = today + timedelta(days=60)
        yaklasan_musabakalar = Musabaka.query.filter(Musabaka.baslama_tarihi >= today,
                                                     Musabaka.baslama_tarihi <= two_months_later).order_by(
            Musabaka.baslama_tarihi).all()

        # Verileri şablona gönderin
        return render_template('yonetici_paneli.html',
                               kulup_sayisi=kulup_sayisi,
                               antrenor_sayisi=antrenor_sayisi,
                               sporcu_sayisi=sporcu_sayisi,
                               hakem_sayisi=hakem_sayisi,
                               kullanici_sayisi=kullanici_sayisi,
                               musabaka_sayisi=musabaka_sayisi,
                               son_kulupler=son_kulupler,
                               son_antrenorler=son_antrenorler,
                               son_sporcular=son_sporcular,
                               son_hakemler=son_hakemler,
                               son_kullanicilar=son_kullanicilar,
                               yaklasan_musabakalar=yaklasan_musabakalar,
                               title='Yönetici Paneli')

    elif role == 'Kulup':
        kulup_id = session.get('kulup_id')  # Örnek olarak kulüp ID'si oturumda saklanıyor varsayılmıştır.

        son_iki_duyuru = Duyuru.query.order_by(Duyuru.yayinlanma_tarihi.desc()).limit(3).all()

        # Kulübe ait sporcu sayısı
        sporcu_sayisi = Sporcu.query.filter_by(kulup_id=kulup_id).count()

        # Kulübe ait antrenör sayısı
        antrenor_sayisi = Antrenor.query.filter_by(kulup_id=kulup_id).count()

        # Kulübün katıldığı müsabakaların sayısını hesapla
        katilimci_musabakalar = db.session.query(Musabaka.id).join(Katilimci).join(Sporcu).filter(
            Sporcu.kulup_id == kulup_id).distinct()
        musabaka_sayisi = katilimci_musabakalar.count()

        # Kulüp bilgilerini çek
        kulup_bilgileri = Kulup.query.filter_by(id=kulup_id).first()

        # Yaklaşan Müsabakalar: Bugünden itibaren sonraki 2 ay içinde başlayacak müsabakalar
        today = datetime.today()
        two_months_later = today + timedelta(days=60)
        yaklasan_musabakalar = Musabaka.query.filter(Musabaka.baslama_tarihi >= today,
                                                     Musabaka.baslama_tarihi <= two_months_later).order_by(
            Musabaka.baslama_tarihi).all()

        # Verileri şablona gönder
        return render_template('kulup_paneli.html',
                               sporcu_sayisi=sporcu_sayisi,
                               antrenor_sayisi=antrenor_sayisi,
                               musabaka_sayisi=musabaka_sayisi,
                               kulup_bilgileri=kulup_bilgileri,
                               yaklasan_musabakalar=yaklasan_musabakalar,
                               duyurular=son_iki_duyuru,
                               title='Kulüp Paneli')

    elif role == 'Antrenor':
        antrenor_id = session.get('antrenor_id')  # Örnek olarak antrenör ID'si oturumda saklanıyor varsayılmıştır.

        # Antrenörün bağlı olduğu kulübü çek
        antrenor_bilgileri = Antrenor.query.filter_by(id=antrenor_id).first()
        kulup_id = antrenor_bilgileri.kulup_id

        # Aynı kulüp ID'sine sahip antrenörleri sayın
        kulup_antrenor_sayisi = Antrenor.query.filter_by(kulup_id=kulup_id).count()

        # Antrenörün bağlı olduğu kulüpteki sporcu sayısını hesapla
        sporcu_sayisi = Sporcu.query.filter_by(kulup_id=kulup_id).count()

        # Antrenörün bağlı olduğu kulüpteki müsabaka sayısını hesapla
        katilimci_musabakalar = db.session.query(Musabaka.id).join(Katilimci).filter(
            Katilimci.antrenor_id == antrenor_id).distinct()
        musabaka_sayisi = katilimci_musabakalar.count()

        # Yaklaşan Müsabakalar: Bugünden itibaren sonraki 2 ay içinde başlayacak müsabakalar
        today = datetime.today()

        two_months_later = today + timedelta(days=60)
        yaklasan_musabakalar = Musabaka.query.filter(Musabaka.baslama_tarihi >= today,
                                                     Musabaka.baslama_tarihi <= two_months_later).order_by(
            Musabaka.baslama_tarihi).all()

        # Duyuruları çek
        son_iki_duyuru = Duyuru.query.order_by(Duyuru.yayinlanma_tarihi.desc()).limit(2).all()

        # Verileri şablona gönderin
        return render_template('antrenor_paneli.html',
                               sporcu_sayisi=sporcu_sayisi,
                               musabaka_sayisi=musabaka_sayisi,
                               antrenor_bilgileri=antrenor_bilgileri,
                               yaklasan_musabakalar=yaklasan_musabakalar,
                               duyurular=son_iki_duyuru,  # En son iki duyuru
                               kulup_antrenor_sayisi=kulup_antrenor_sayisi,  # Kulübe bağlı antrenör sayısı
                               title='Antrenör Paneli')

    elif role == 'IlTemsilcisi':
        il_temsilcisi_id = session.get('il_temsilcisi_id')  # Kullanıcının il temsilcisi ID'si
        il_temsilcisi_bilgileri = IlTemsilcisi.query.filter_by(id=il_temsilcisi_id).first()

        # İl temsilcisine bağlı sporcu sayısı
        sporcu_sayisi = Sporcu.query.filter_by(il_temsilcisi_id=il_temsilcisi_id).count()

        katildigi_musabakalar = db.session.query(Musabaka.id) \
            .join(Katilimci) \
            .filter(Katilimci.sporcu_id == Sporcu.id, Sporcu.il_temsilcisi_id == il_temsilcisi_id) \
            .distinct() \
            .count()

        # İl temsilcisinin ilinde düzenlenen müsabaka sayısı
        ildeki_musabaka_sayisi = Musabaka.query.filter_by(il=il_temsilcisi_bilgileri.il).count()

        # Yaklaşan Müsabakalar: Bugünden itibaren sonraki 2 ay içinde başlayacak müsabakalar
        today = datetime.today()
        two_months_later = today + timedelta(days=60)
        yaklasan_musabakalar = Musabaka.query.filter(Musabaka.baslama_tarihi >= today,
                                                     Musabaka.baslama_tarihi <= two_months_later).order_by(
            Musabaka.baslama_tarihi).all()

        # Duyuruları çek
        son_iki_duyuru = Duyuru.query.order_by(Duyuru.yayinlanma_tarihi.desc()).limit(3).all()

        # Verileri şablona gönder
        return render_template('iltemsilcisi_paneli.html',
                               sporcu_sayisi=sporcu_sayisi,
                               katildigi_musabakalar=katildigi_musabakalar,
                               ildeki_musabaka_sayisi=ildeki_musabaka_sayisi,
                               il_temsilcisi_bilgileri=il_temsilcisi_bilgileri,
                               yaklasan_musabakalar=yaklasan_musabakalar,
                               duyurular=son_iki_duyuru,
                               title='İl Temsilcisi Paneli')

    elif role == 'Hakem':
        hakem_id = session.get('hakem_id')
        hakem_bilgileri = Hakem.query.filter_by(id=hakem_id).first()
        musabaka_sayisi = Musabaka.query.count()

        # Hakemin görev aldığı müsabaka sayısı
        hakemin_musabaka_sayisi = db.session.query(Musabaka.id).join(musabaka_hakem).filter(
            musabaka_hakem.c.hakem_id == hakem_id).count()

        # Hakemin ilinde düzenlenen toplam müsabaka sayısı
        ildeki_musabaka_sayisi = Musabaka.query.filter_by(il=hakem_bilgileri.il).count()

        # Yaklaşan Müsabakalar
        today = datetime.today()
        two_months_later = today + timedelta(days=60)
        yaklasan_musabakalar = Musabaka.query.filter(Musabaka.baslama_tarihi >= today,
                                                     Musabaka.baslama_tarihi <= two_months_later).order_by(
            Musabaka.baslama_tarihi).all()

        # Son iki duyuru
        son_iki_duyuru = Duyuru.query.order_by(Duyuru.yayinlanma_tarihi.desc()).limit(3).all()

        # Verileri şablona gönder
        return render_template('hakem_paneli.html',
                               hakem_bilgileri=hakem_bilgileri,
                               hakemin_musabaka_sayisi=hakemin_musabaka_sayisi,
                               ildeki_musabaka_sayisi=ildeki_musabaka_sayisi,
                               yaklasan_musabakalar=yaklasan_musabakalar,
                               duyurular=son_iki_duyuru,
                               musabaka_sayisi=musabaka_sayisi,
                               title='Hakem Paneli')

    else:
        # Eğer rol tanımlı değilse veya başka bir rol ise, login sayfasına geri yönlendir
        flash('Yetkisiz erişim!', 'danger')
        return redirect(url_for('login'))


# Yönetici listesi görüntüleme fonksiyonunda, her bir yöneticinin fotoğrafının kontrol edilmesi
@app.route('/yoneticiler')
@login_required
@check_permission('Yonetici')
def yonetici_listesi():
    yoneticiler = Yonetici.query.all()
    for yonetici in yoneticiler:
        if not yonetici.foto:
            yonetici.foto = 'default.jpg'  # Varsayılan bir fotoğraf adı veya boş bir string
    return render_template('yonetici_listesi.html', yoneticiler=yoneticiler, title='Yönetici Listesi')


@app.route('/yonetici/ekle', methods=['GET', 'POST'])
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def yonetici_ekle():
    if request.method == 'POST':
        # Form verilerini al
        tc_kimlik_no = request.form.get('tc_kimlik_no')
        ad_soyad = request.form.get('ad_soyad')
        gorevi = request.form.get('gorevi')
        telefon = request.form.get('telefon')
        eposta = request.form.get('eposta')
        adres = request.form.get('adres')
        il = request.form.get('il')
        kullanici_adi = request.form.get('kullanici_adi')  # Kullanıcı adını formdan al
        sifre = request.form.get('sifre')  # Şifreyi formdan al

        # Fotoğrafı dosya yükleme alanından al
        foto = request.files.get('foto')

        # Şifreyi hash'le ve yeni kullanıcıyı oluştur
        sifre_hashed = generate_password_hash(sifre) if sifre else None
        yeni_kullanici = Kullanici(kullanici_adi=kullanici_adi, sifre=sifre_hashed, rol=Rol.Yonetici)

        # Fotoğrafı kaydet
        filename = None
        if foto and allowed_file(foto.filename):
            filename = secure_filename(f'yonetici_{tc_kimlik_no}.jpg')
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Kullanıcıyı veritabanına ekle
        db.session.add(yeni_kullanici)
        db.session.flush()  # Yeni kullanıcının ID'sini alabilmek için

        # Yeni yöneticiyi oluştur ve veritabanına ekle
        yeni_yonetici = Yonetici(
            ad_soyad=ad_soyad,
            gorevi=gorevi,
            telefon=telefon,
            eposta=eposta,
            adres=adres,
            il=il,
            kullanici_id=yeni_kullanici.id,
            foto=filename,
            tc_kimlik_no=tc_kimlik_no
        )
        db.session.add(yeni_yonetici)
        db.session.commit()

        return redirect(url_for('yonetici_listesi'))

    return render_template('yonetici_ekle.html', title='Yönetici Ekle')


@app.route('/yonetici/duzenle/<int:id>', methods=['GET', 'POST'])
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def yonetici_duzenle(id):
    yonetici = Yonetici.query.get_or_404(id)
    kullanici = Kullanici.query.get_or_404(yonetici.kullanici_id)

    if request.method == 'POST':
        # Yönetici bilgilerini güncelle
        yonetici.ad_soyad = request.form['ad_soyad']
        yonetici.gorevi = request.form['gorevi']
        yonetici.telefon = request.form['telefon']
        yonetici.eposta = request.form['eposta']
        yonetici.adres = request.form['adres']
        yonetici.il = request.form['il']
        yonetici.tc_kimlik_no = request.form['tc_kimlik_no']  # T.C. Kimlik numarasını güncelle

        # Kullanıcı adı ve şifre güncelleme
        kullanici_adi = request.form['kullanici_adi']
        sifre = request.form['sifre']
        if kullanici_adi:
            kullanici.kullanici_adi = kullanici_adi
        if sifre:
            kullanici.sifre = generate_password_hash(sifre)

        # Fotoğraf güncelleme
        foto = request.files.get('foto')
        if foto and allowed_file(foto.filename):
            if yonetici.foto:
                # Eski fotoğrafı sil
                eski_foto_path = os.path.join(app.config['UPLOAD_FOLDER'], yonetici.foto)
                if os.path.exists(eski_foto_path):
                    os.remove(eski_foto_path)
            # Yeni fotoğrafı kaydet
            filename = secure_filename(f'yonetici_{yonetici.tc_kimlik_no}.jpg')
            foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            foto.save(foto_path)
            yonetici.foto = filename

        db.session.commit()

        return redirect(url_for('yonetici_listesi'))

    return render_template('yonetici_duzenle.html', yonetici=yonetici, kullanici=kullanici, title='Yönetici Düzenle')


@app.route('/yonetici/sil/<int:id>', methods=['POST'])
@login_required
@check_permission('Yonetici')
def yonetici_sil(id):
    yonetici = Yonetici.query.get_or_404(id)
    kullanici = Kullanici.query.get_or_404(yonetici.kullanici_id)

    # Online kullanıcı kayıtlarını sil
    online_kullanici_kayitlari = OnlineKullanici.query.filter_by(kullanici_id=kullanici.id).all()
    for kayit in online_kullanici_kayitlari:
        db.session.delete(kayit)

    # Kullanıcı geçmiş kayıtlarını sil
    kullanici_gecmis_kayitlari = KullaniciGecmis.query.filter_by(kullanici_id=kullanici.id).all()
    for kayit in kullanici_gecmis_kayitlari:
        db.session.delete(kayit)

    # Eğer bir fotoğraf varsa sil
    if yonetici.foto:
        foto_path = os.path.join(current_app.config['UPLOAD_FOLDER'], yonetici.foto)
        if os.path.exists(foto_path):
            os.remove(foto_path)

    # Yöneticiyi ve ilgili kullanıcıyı veritabanından sil
    db.session.delete(yonetici)
    db.session.delete(kullanici)
    db.session.commit()

    flash(f"{yonetici.ad_soyad} yöneticisi başarıyla silindi.")
    return redirect(url_for('yonetici_listesi'))


@app.route('/toggle-user-status/<int:id>', methods=['POST'])
@login_required
@check_permission('Yonetici')
def toggle_user_status(id):
    kullanici = Kullanici.query.get_or_404(id)
    kullanici.aktif = not kullanici.aktif
    db.session.commit()
    flash(f"Kullanıcı {'aktifleştirildi' if kullanici.aktif else 'pasifleştirildi'}.")
    return redirect(url_for('kullanici_listesi'))


@app.route('/kullanicilar')
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def kullanici_listesi():
    # Kullanıcı rolünü kontrol et
    if session.get('role') != 'Yonetici':
        flash('Bu sayfayı görüntüleme yetkiniz yok!')
        return redirect(url_for('dashboard'))

    # Kullanıcıları ve ilişkili ek bilgileri sorgula
    kullanici_listem = db.session.query(
        Kullanici
    ).outerjoin(Kulup, Kullanici.id == Kulup.kullanici_id) \
        .outerjoin(IlTemsilcisi, Kullanici.id == IlTemsilcisi.kullanici_id) \
        .outerjoin(Antrenor, Kullanici.id == Antrenor.kullanici_id) \
        .outerjoin(Hakem, Kullanici.id == Hakem.kullanici_id) \
        .outerjoin(Yonetici, Kullanici.id == Yonetici.kullanici_id) \
        .add_columns(
        Kulup.kulup_adi,
        IlTemsilcisi.ad_soyad.label('iltemsilcisi_ad_soyad'),
        Antrenor.ad_soyad.label('antrenor_ad_soyad'),
        Hakem.ad_soyad.label('hakem_ad_soyad'),
        Yonetici.ad_soyad.label('yonetici_ad_soyad'),
    ).all()

    # Döngü içinde kullanıcılar listesini ve ilgili rolleri işleyecek şekilde şablonu güncelleyin
    return render_template('kullanici_listesi.html', kullanicilar=kullanici_listem, title='Kullanıcı Listesi')


@app.route('/kullanici-guncelle/<int:id>', methods=['GET', 'POST'])
@login_required
def kullanici_guncelle(id):
    # Veritabanından ilgili kullanıcıyı çek
    kullanici = Kullanici.query.get_or_404(id)
    antrenor = Antrenor.query.filter_by(kullanici_id=id).first()

    # Oturum açan kullanıcının ID ve rolünü al
    current_user_id = session.get('user_id')
    current_user_role = session.get('role')

    # Kullanıcı ve antrenörün kulüp yetkilisi kontrolü
    if current_user_role != 'Yonetici':
        if antrenor and antrenor.kullanici_id == current_user_id:
            # Antrenör kendi bilgilerini güncelliyorsa bu izin verilir
            pass
        elif antrenor:
            kulup = Kulup.query.get(antrenor.kulup_id)
            if not (kulup and kulup.kullanici_id == current_user_id):
                flash('Bu işlem için yetkiniz yok!', 'error')
                return redirect(url_for('dashboard'))
        elif id != current_user_id:
            flash('Bu işlem için yetkiniz yok!', 'error')
            return redirect(url_for('dashboard'))

    ilgili_isim_tipi = 'Kisi'  # Varsayılan olarak 'Kisi' tipinde olduğunu varsayalım

    # İlgili isimleri elde etmek için ek sorgulamalar
    ilgili_isim = ''
    if kullanici.rol == Rol.Kulup:
        ilgili_kulup = Kulup.query.filter_by(kullanici_id=kullanici.id).first()
        ilgili_isim = ilgili_kulup.kulup_adi if ilgili_kulup else ''
        ilgili_isim_tipi = 'Kulup'
    elif kullanici.rol == Rol.IlTemsilcisi:
        ilgili_il_temsilcisi = IlTemsilcisi.query.filter_by(kullanici_id=kullanici.id).first()
        ilgili_isim = ilgili_il_temsilcisi.ad_soyad if ilgili_il_temsilcisi else ''
    elif kullanici.rol == Rol.Yonetici:
        ilgili_yonetici = Yonetici.query.filter_by(kullanici_id=kullanici.id).first()
        ilgili_isim = ilgili_yonetici.ad_soyad if ilgili_yonetici else ''
    elif kullanici.rol == Rol.Hakem:
        ilgili_hakem = Hakem.query.filter_by(kullanici_id=kullanici.id).first()
        ilgili_isim = ilgili_hakem.ad_soyad if ilgili_hakem else ''
    elif kullanici.rol == Rol.Antrenor:
        ilgili_antrenor = Antrenor.query.filter_by(kullanici_id=kullanici.id).first()
        ilgili_isim = ilgili_antrenor.ad_soyad if ilgili_antrenor else ''
    # Diğer roller için benzer sorgulamalar...

    if request.method == 'POST':
        yeni_kullanici_adi = request.form['kullanici_adi']

        # Kullanıcı adı benzersizlik kontrolü
        mevcut_kullanici = Kullanici.query.filter(
            Kullanici.kullanici_adi == yeni_kullanici_adi,
            Kullanici.id != id
        ).first()

        if mevcut_kullanici:
            # Kullanıcı adı zaten kullanımda, uyarı mesajı göster
            flash('Bu kullanıcı adı zaten kullanımda. Lütfen farklı bir kullanıcı adı seçin.', 'error')
        else:
            # Kullanıcı adı benzersiz, güncelleme işlemini yap
            kullanici.kullanici_adi = yeni_kullanici_adi
            if request.form['yeni_sifre']:
                kullanici.sifre = generate_password_hash(request.form['yeni_sifre'])

            db.session.commit()
            flash('Kullanıcı başarıyla güncellendi.', 'success')

    # GET isteği ve diğer durumlar için kullanıcı güncelleme formunu hazırla
    return render_template('kullanici_guncelle.html', kullanici=kullanici,
                           ilgili_isim=ilgili_isim, ilgili_isim_tipi=ilgili_isim_tipi, title='Kullanıcı Güncelle')


@app.route('/kullanici-sil/<int:id>', methods=['POST'])
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def kullanici_sil(id):
    kullanici = Kullanici.query.get_or_404(id)

    # Kullanıcıya bağlı yöneticiler kayıtlarını sil
    yonetici_kayitlari = Yonetici.query.filter_by(kullanici_id=kullanici.id).all()
    for yonetici in yonetici_kayitlari:
        db.session.delete(yonetici)

    # Online kullanıcılara bağlı kayıtları sil
    online_kullanici_kayitlari = OnlineKullanici.query.filter_by(kullanici_id=kullanici.id).all()
    for online_kullanici in online_kullanici_kayitlari:
        db.session.delete(online_kullanici)

    # Kullanıcı geçmiş kayıtlarını sil
    kullanici_gecmis_kayitlari = KullaniciGecmis.query.filter_by(kullanici_id=kullanici.id).all()
    for gecmis in kullanici_gecmis_kayitlari:
        db.session.delete(gecmis)

    # Kullanıcıyı veritabanından sil
    db.session.delete(kullanici)
    db.session.commit()

    flash('Kullanıcı ve ilgili veriler başarıyla silindi.', 'success')
    return redirect(url_for('kullanici_listesi'))


@app.route('/kulupler')
@login_required
def kulup_listesi():
    kullanici_id = session.get('user_id')

    # Kullanıcıya ait hakemi kontrol et
    hakem = Hakem.query.filter_by(kullanici_id=kullanici_id).first()

    # Eğer kullanıcı bir hakemse, erişimi engelle
    if hakem:
        flash('Hakemlerin bu sayfaya erişim yetkisi yok.', 'danger')
        return redirect(url_for('dashboard'))

    # Kullanıcıya ait antrenörü kontrol et
    antrenor = Antrenor.query.filter_by(kullanici_id=kullanici_id).first()

    # Eğer kullanıcı bir antrenörse ve bir kulübe aitse, kendi kulübünün detay sayfasına yönlendir
    if antrenor:
        return redirect(url_for('kulup_detay', kulup_id=antrenor.kulup_id))

    # Eğer kullanıcı bir kulüple ilişkilendirilmişse, kendi kulüp detay sayfasına yönlendir
    kulup = Kulup.query.filter_by(kullanici_id=kullanici_id).first()
    if kulup:
        return redirect(url_for('kulup_detay', kulup_id=kulup.id))

    # Kullanıcı ne bir kulüple ne de bir antrenörle ilişkilendirilmişse, tüm kulüpleri listeleyin
    kulupler = Kulup.query.join(Kullanici, Kulup.kullanici_id == Kullanici.id).add_columns(
        Kulup.id,
        Kulup.kulup_adi,
        Kulup.kutuk_no,
        Kulup.baskan_adi,
        Kulup.telefon,
        Kulup.eposta,
        Kulup.il,
        Kulup.logo_url,  # Logo URL'sini de ekleyin
        Kullanici.kullanici_adi
    ).all()
    return render_template('kulup_listesi.html', kulupler=kulupler, title='Kulüpler')


@app.route('/kulup/<int:kulup_id>/detay')
@login_required
def kulup_detay(kulup_id):
    kullanici_id = session.get('user_id')
    kullanici_rol = session.get('role')

    # Kullanıcıya ait kulübü ve antrenör bilgisini al
    kullanici_kulup = Kulup.query.filter_by(kullanici_id=kullanici_id).first()
    kullanici_antrenor = Antrenor.query.filter_by(kullanici_id=kullanici_id).first()

    # Eğer kullanıcı bir kulüp yöneticisi veya antrenör ise ve ilgili kulüp ID'si uyuşuyorsa,
    # veya kullanıcı bir yönetici ise detay sayfasını göster
    if kullanici_rol == 'Yonetici' or (kullanici_kulup and kullanici_kulup.id == kulup_id) or \
            (kullanici_antrenor and kullanici_antrenor.kulup_id == kulup_id):
        kulup = Kulup.query.get_or_404(kulup_id)
        sporcular = Sporcu.query.filter_by(kulup_id=kulup_id).all()
        antrenorler = Antrenor.query.filter_by(kulup_id=kulup_id).all()
        sporcu_ids = [sporcu.id for sporcu in sporcular]
        musabakalar = Musabaka.query.join(Katilimci, Musabaka.id == Katilimci.musabaka_id) \
            .filter(Katilimci.sporcu_id.in_(sporcu_ids)).all()

        for musabaka in musabakalar:
            musabaka.katilan_sporcular = Sporcu.query.join(Katilimci, Sporcu.id == Katilimci.sporcu_id) \
                .filter(Katilimci.musabaka_id == musabaka.id, Sporcu.kulup_id == kulup_id).all()
            musabaka.katilan_antrenorler = Antrenor.query.join(Katilimci, Antrenor.id == Katilimci.antrenor_id) \
                .filter(Katilimci.musabaka_id == musabaka.id, Antrenor.kulup_id == kulup_id).all()

        return render_template('kulup_detay.html', kulup=kulup, sporcular=sporcular,
                               antrenorler=antrenorler, musabakalar=musabakalar,
                               title='Kulüp Detay', current_user_id=kullanici_id)

    # Eğer kullanıcı yetkili değilse, erişimi reddet ve uyarı mesajı göster
    flash('Bu kulübün detaylarına erişim yetkiniz yok.', 'danger')
    return redirect(url_for('dashboard'))


@app.route('/kulup-ekle', methods=['GET', 'POST'])
@login_required
@check_permission('Yonetici')
def kulup_ekle():
    if request.method == 'POST':
        # Kullanıcı bilgilerini al ve işle
        kullanici_adi = request.form.get('kullanici_adi')
        sifre = request.form.get('sifre')
        hashed_sifre = generate_password_hash(sifre)

        yeni_kullanici = Kullanici(
            kullanici_adi=kullanici_adi,
            sifre=hashed_sifre,
            rol=Rol.Kulup
        )
        db.session.add(yeni_kullanici)
        db.session.commit()

        # Kulüp bilgilerini al
        kulup_adi = request.form.get('kulup_adi')
        kutuk_no = request.form.get('kutuk_no')
        baskan_adi = request.form.get('baskan_adi')
        telefon = request.form.get('telefon')
        eposta = request.form.get('eposta')
        iban = request.form.get('iban')
        adres = request.form.get('adres')
        il = request.form.get('il')

        # Logo dosyasını işle ve kaydet
        logo = request.files['logo']
        logo_url = None
        if logo:
            filename = secure_filename(f"kulup_{kutuk_no}.jpg")
            logo.save(os.path.join('static/uploads', filename))
            logo_url = filename  # Sadece dosya adını kaydet

        # Yeni kulüp nesnesi oluştur
        yeni_kulup = Kulup(
            kulup_adi=kulup_adi,
            kutuk_no=kutuk_no,
            baskan_adi=baskan_adi,
            telefon=telefon,
            eposta=eposta,
            iban=iban,
            adres=adres,
            il=il,
            kullanici_id=yeni_kullanici.id,
            logo_url=logo_url  # Güncellenmiş logo URL'sini ekle
        )
        db.session.add(yeni_kulup)
        db.session.commit()

        flash('Kulüp ve kullanıcı başarıyla eklendi!', 'success')
        return redirect(url_for('kulup_listesi'))

    return render_template('kulup_ekle.html', title='Kulüp Ekle')


@app.route('/kulup-guncelle/<int:kulup_id>', methods=['GET', 'POST'])
@login_required
def kulup_guncelle(kulup_id):
    kulup = Kulup.query.get_or_404(kulup_id)

    # Kullanıcının yetkisini kontrol et
    if session.get('user_id') != kulup.kullanici_id and session.get('role') != 'Yonetici':
        flash('Bu sayfayı görüntüleme yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Kulüp bilgilerini güncelle
        kulup.kulup_adi = request.form.get('kulup_adi')
        kulup.kutuk_no = request.form.get('kutuk_no')
        kulup.baskan_adi = request.form.get('baskan_adi')
        kulup.telefon = request.form.get('telefon')
        kulup.eposta = request.form.get('eposta')
        kulup.iban = request.form.get('iban')
        kulup.adres = request.form.get('adres')
        kulup.il = request.form.get('il')

        # Logo dosyasını işle ve kaydet
        logo = request.files.get('logo')
        if logo and logo.filename != '':
            filename = secure_filename(f"kulup_{kulup.kutuk_no}.jpg")
            logo.save(os.path.join('static/uploads', filename))
            kulup.logo_url = filename  # Sadece dosya adını kaydet

        db.session.commit()
        flash('Kulüp bilgileri başarıyla güncellendi!', 'success')
        return redirect(url_for('kulup_listesi'))

    return render_template('kulup_guncelle.html', kulup=kulup, title='Kulüp Güncelle')


@app.route('/kulup-sil/<int:kulup_id>', methods=['POST'])
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def kulup_sil(kulup_id):
    # Silinecek kulübü bul
    kulup = Kulup.query.get_or_404(kulup_id)
    kullanici_id = kulup.kullanici_id

    # Veritabanından kulübü sil
    db.session.delete(kulup)

    # İlişkili kullanıcıyı bul
    kullanici = Kullanici.query.get(kullanici_id)
    if kullanici:
        # Kullanıcıya bağlı geçmiş kayıtları sil
        kullanici_gecmis_kayitlari = KullaniciGecmis.query.filter_by(kullanici_id=kullanici.id).all()
        for gecmis in kullanici_gecmis_kayitlari:
            db.session.delete(gecmis)

        # Online kullanıcı kayıtlarını sil
        online_kullanici_kayitlari = OnlineKullanici.query.filter_by(kullanici_id=kullanici.id).all()
        for online_kullanici in online_kullanici_kayitlari:
            db.session.delete(online_kullanici)

        # Kullanıcıyı sil
        db.session.delete(kullanici)

    # Değişiklikleri veritabanına kaydet
    try:
        db.session.commit()
        flash('Kulüp ve ilişkili kullanıcı başarıyla silindi!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Bir hata oluştu: {str(e)}', 'danger')

    return redirect(url_for('kulup_listesi'))


@app.route('/il_temsilcileri')
@login_required
def il_temsilcileri_listesi():
    kullanici_id = session.get('user_id')
    kullanici_rol = session.get('role')  # 'user_role' yerine 'role' kullan

    # Antrenörler, kulüpler ve hakemlerin girişine izin verme
    if kullanici_rol not in ['IlTemsilcisi', 'Yonetici']:
        flash('Bu sayfaya erişim yetkiniz bulunmamaktadır.', 'error')
        return redirect(url_for('dashboard'))

    # Kullanıcının il temsilcisi olup olmadığını kontrol et
    il_temsilcisi = IlTemsilcisi.query.filter_by(kullanici_id=kullanici_id).first()

    # Eğer kullanıcı bir il temsilcisiyse, kendi detay sayfasına yönlendir
    if il_temsilcisi:
        return redirect(url_for('il_temsilcisi_detay', il_temsilcisi_id=il_temsilcisi.id))

    # Kullanıcı bir il temsilcisi değilse, tüm il temsilcilerinin listesini göster
    il_temsilcileri = IlTemsilcisi.query.all()
    return render_template('il_temsilcileri_listesi.html', il_temsilcileri=il_temsilcileri, title='İl Temsilcileri')


@app.route('/il_temsilcisi/<int:il_temsilcisi_id>/detay')
@login_required
def il_temsilcisi_detay(il_temsilcisi_id):
    # Kullanıcının rolünü kontrol et
    kullanici_rol = session.get('role')  # 'user_role' yerine 'role' kullanılmalı
    if kullanici_rol not in ['IlTemsilcisi', 'Yonetici']:
        flash('Bu sayfayı görüntüleme yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    # Oturum bilgilerini kontrol et
    if 'il_temsilcisi_id' in session and session['il_temsilcisi_id'] != il_temsilcisi_id:
        flash('Bu sayfayı görüntüleme yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    # İl temsilcisini ID'ye göre sorgula
    il_temsilcisi = IlTemsilcisi.query.get_or_404(il_temsilcisi_id)
    # İl temsilcisine bağlı sporcuları sorgula
    sporcular = Sporcu.query.filter_by(il_temsilcisi_id=il_temsilcisi_id).all()

    # İl temsilcisine bağlı sporcuların katıldığı müsabakaları sorgula
    musabaka_ids = set()
    for sporcu in sporcular:
        katilimlar = Katilimci.query.filter_by(sporcu_id=sporcu.id).all()
        for katilim in katilimlar:
            musabaka_ids.add(katilim.musabaka_id)

    # Müsabakaları sorgula
    musabakalar = Musabaka.query.filter(Musabaka.id.in_(musabaka_ids)).all()

    # Her müsabaka için il temsilcisine bağlı katılan sporcuları sorgula
    for musabaka in musabakalar:
        musabaka.katilan_sporcular = Sporcu.query \
            .join(Katilimci, Sporcu.id == Katilimci.sporcu_id) \
            .filter(Katilimci.musabaka_id == musabaka.id, Sporcu.il_temsilcisi_id == il_temsilcisi_id) \
            .all()

    return render_template('il_temsilcisi_detay.html', il_temsilcisi=il_temsilcisi, sporcular=sporcular,
                           musabakalar=musabakalar, title='İl Temsilcisi Detay')


@app.route('/il_temsilcisi_ekle', methods=['GET', 'POST'])
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def il_temsilcisi_ekle():
    if request.method == 'POST':
        # Kullanıcı bilgilerini al
        kullanici_adi = request.form['kullanici_adi']
        sifre = request.form['sifre']
        # Kullanıcı nesnesini oluştur
        yeni_kullanici = Kullanici(
            kullanici_adi=kullanici_adi,
            sifre=generate_password_hash(sifre),
            rol=Rol.IlTemsilcisi.name,
            aktif=True
        )
        db.session.add(yeni_kullanici)
        db.session.commit()

        # İl Temsilcisi bilgilerini al
        ad_soyad = request.form['ad_soyad']
        il = request.form['il']
        telefon = request.form['telefon']
        eposta = request.form['eposta']
        tc_kimlik_no = request.form['tc_kimlik_no']  # TC kimlik numarası formdan alınır
        foto = request.files['foto']  # Fotoğraf formdan alınır

        filename = None
        if foto and allowed_file(foto.filename):  # Fotoğrafın uygun bir dosya olduğunu kontrol edin
            filename = secure_filename(f"iltemsilcisi_{tc_kimlik_no}.{foto.filename.rsplit('.', 1)[1].lower()}")
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        yeni_temsilci = IlTemsilcisi(
            ad_soyad=ad_soyad,
            il=il,
            telefon=telefon,
            eposta=eposta,
            tc_kimlik_no=tc_kimlik_no,
            foto=filename,
            kullanici_id=yeni_kullanici.id
        )
        db.session.add(yeni_temsilci)

        try:
            db.session.commit()
            flash('İl temsilcisi başarıyla eklendi.', 'success')
            return redirect(url_for('il_temsilcileri_listesi'))
        except Exception as e:
            db.session.rollback()
            flash(f'Bir hata oluştu: {e}', 'error')

    return render_template('il_temsilcisi_ekle.html', title='İl Temsilcisi Ekle')


@app.route('/il_temsilcisi/<int:id>/duzenle', methods=['GET', 'POST'])
@login_required
def il_temsilcisi_duzenle(id):
    temsilci = IlTemsilcisi.query.get_or_404(id)
    kullanici = temsilci.kullanici  # IlTemsilcisi ile ilişkili Kullanici nesnesine erişim

    # Kullanıcı yetkisini kontrol et
    if session.get('user_id') != temsilci.kullanici_id and session.get('role') != 'Yonetici':
        flash('Bu işlemi yapmaya yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Temsilci bilgilerini güncelle
        temsilci.ad_soyad = request.form['ad_soyad']
        temsilci.il = request.form['il']
        temsilci.telefon = request.form['telefon']
        temsilci.eposta = request.form['eposta']
        temsilci.adres = request.form['adres']
        temsilci.tc_kimlik_no = request.form['tc_kimlik_no']  # TC Kimlik No bilgisini güncelle

        # Fotoğraf güncellemesi
        foto = request.files['foto']
        if foto and allowed_file(foto.filename):
            filename = secure_filename(
                f"iltemsilcisi_{temsilci.tc_kimlik_no}.{foto.filename.rsplit('.', 1)[1].lower()}")
            foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            # Eski fotoğrafı sil
            eski_foto_path = os.path.join(app.config['UPLOAD_FOLDER'], temsilci.foto) if temsilci.foto else None
            if eski_foto_path and os.path.exists(eski_foto_path) and os.path.isfile(eski_foto_path):
                os.remove(eski_foto_path)
            # Yeni fotoğrafı kaydet
            foto.save(foto_path)
            temsilci.foto = filename  # Fotoğraf bilgisini güncelle

        # Kullanıcı bilgilerini güncelle
        kullanici.kullanici_adi = request.form.get('kullanici_adi', kullanici.kullanici_adi)
        yeni_sifre = request.form.get('yeni_sifre')
        if yeni_sifre:
            kullanici.sifre = generate_password_hash(yeni_sifre)

        try:
            db.session.commit()
            flash('İl temsilcisi başarıyla güncellendi.', 'success')
            return redirect(url_for('il_temsilcileri_listesi'))
        except Exception as e:
            db.session.rollback()
            flash(f'Bir hata oluştu: {e}', 'error')

    return render_template('il_temsilcisi_duzenle.html', temsilci=temsilci, kullanici=kullanici,
                           title='İl Temsilcisi Düzenle')


@app.route('/il_temsilcisi/<int:id>/sil', methods=['POST'])
@login_required
def il_temsilcisi_sil(id):
    temsilci = IlTemsilcisi.query.get_or_404(id)
    db.session.delete(temsilci)
    try:
        db.session.commit()
        flash('İl temsilcisi başarıyla silindi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Bir hata oluştu: {e}', 'error')
    return redirect(url_for('il_temsilcileri_listesi'))


@app.route('/yas_kategori_listesi')
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def yas_kategori_listesi():
    yas_kategorileri = YasKategorisi.query.all()
    return render_template('yas_kategori_listesi.html', yas_kategorileri=yas_kategorileri, title='Yaş Kategori Listesi')


@app.route('/yas_kategori_ekle', methods=['GET', 'POST'])
@login_required
def yas_kategori_ekle():
    if request.method == 'POST':
        yas_kategori_adi = request.form.get('yas_kategori_adi')

        # Yaş kategorisi nesnesi oluşturun
        yeni_kategori = YasKategorisi(yas_kategori_adi=yas_kategori_adi)

        # Veritabanına ekle
        db.session.add(yeni_kategori)
        try:
            db.session.commit()
            flash('Yaş kategorisi başarıyla eklendi.', 'success')
            return redirect(url_for('yas_kategori_listesi'))
        except Exception as e:
            db.session.rollback()
            flash('Yaş kategorisi eklenirken bir hata oluştu. Hata: ' + str(e), 'error')
            return redirect(url_for('yas_kategori_ekle'))

    # GET request için formu göster

    return render_template('yas_kategori_ekle.html', title='Yaş Kategorisi Ekle')


@app.route('/yas-kategori-sil/<int:id>', methods=['POST'])
@login_required
def yas_kategori_sil(id):
    # Yaş kategorisini bul ve sil
    kategori = YasKategorisi.query.get_or_404(id)
    db.session.delete(kategori)
    db.session.commit()
    flash('Yaş kategorisi başarıyla silindi.', 'success')
    return redirect(url_for('yas_kategori_listesi'))


@app.route('/sporcu_listesi')
@login_required
def sporcu_listesi():
    kullanici_id = session.get('user_id')

    # Kullanıcıya ait hakemi kontrol et
    hakem = Hakem.query.filter_by(kullanici_id=kullanici_id).first()

    # Eğer kullanıcı bir hakemse, erişimi engelle
    if hakem:
        flash('Hakemlerin bu sayfaya erişim yetkisi yok.', 'danger')
        return redirect(url_for('dashboard'))  # Varsayılan bir başka sayfaya yönlendirme

    kulup = Kulup.query.filter_by(kullanici_id=kullanici_id).first()
    il_temsilcisi = IlTemsilcisi.query.filter_by(kullanici_id=kullanici_id).first()
    antrenor = Antrenor.query.filter_by(kullanici_id=kullanici_id).first()  # Antrenör kontrolü

    # Eğer kullanıcı bir antrenör ise, ilişkilendirildiği kulübün transfer edilmemiş sporcularını getir
    if antrenor:
        sporcular = Sporcu.query.filter(Sporcu.kulup_id == antrenor.kulup_id, Sporcu.transfer_edildi == False).all()
    # Kullanıcı bir kulüple ilişkilendirilmişse, sadece o kulübün transfer edilmemiş sporcularını getir
    elif kulup:
        sporcular = Sporcu.query.filter(Sporcu.kulup_id == kulup.id, Sporcu.transfer_edildi == False).all()
    # Kullanıcı bir il temsilcisi ise, kendi il temsilciliği ile ilişkilendirilmiş transfer edilmemiş sporcuları getir
    elif il_temsilcisi:
        sporcular = Sporcu.query.filter(Sporcu.il_temsilcisi_id == il_temsilcisi.id, Sporcu.transfer_edildi == False).all()
    else:
        # Yöneticiler ve diğer durumlar için, tüm sporcuları getir
        sporcular = Sporcu.query.all()

    return render_template('sporcu_listesi.html', sporcular=sporcular, title='Sporcu Listesi')



@app.route('/sporcu/<int:sporcu_id>/detay')
@login_required
def sporcu_detay(sporcu_id):
    # Kullanıcının ID'sini ve rolünü al
    kullanici_id = session.get('user_id')
    kullanici_rol = session.get('role')

    # Sporcu bilgisini al
    sporcu = Sporcu.query.get_or_404(sporcu_id)

    # Kullanıcı bir hakemse erişimi reddet
    if kullanici_rol == 'Hakem':
        flash('Bu sporcunun detaylarına erişim yetkiniz yok.', 'danger')
        return redirect(url_for('sporcu_listesi'))  # Kullanıcıyı sporcu listesi sayfasına yönlendir

    # Kullanıcı bir il temsilcisi ise ve sporcu onun sorumluluk alanında değilse, erişimi reddet
    if kullanici_rol == 'IlTemsilcisi':
        il_temsilcisi = IlTemsilcisi.query.filter_by(kullanici_id=kullanici_id).first()
        if not il_temsilcisi or sporcu.il_temsilcisi_id != il_temsilcisi.id:
            flash('Bu sporcunun detaylarına erişim yetkiniz yok.', 'danger')
            return redirect(url_for('sporcu_listesi'))

    # Kullanıcı bir antrenörse ve sporcu o antrenörün kulübüne ait değilse, erişimi reddet
    if kullanici_rol == 'Antrenor':
        antrenor = Antrenor.query.filter_by(kullanici_id=kullanici_id).first()
        if not antrenor or sporcu.kulup_id != antrenor.kulup_id:
            flash('Bu sporcunun detaylarına erişim yetkiniz yok.', 'danger')
            return redirect(url_for('sporcu_listesi'))

    # Kullanıcı bir kulüpse ve sporcu o kulübe ait değilse, erişimi reddet
    elif kullanici_rol == 'Kulup':
        kulup = Kulup.query.filter_by(kullanici_id=kullanici_id).first()
        if not kulup or sporcu.kulup_id != kulup.id:
            flash('Bu sporcunun detaylarına erişim yetkiniz yok.', 'danger')
            return redirect(url_for('sporcu_listesi'))

    # Kulübe ait antrenörleri al
    antrenorler = Antrenor.query.filter_by(kulup_id=sporcu.kulup_id).all() if sporcu.kulup_id else []

    # Sporcunun katıldığı müsabakaları ve sonuçlarını al
    musabakalar = []
    sporcu_musabaka_sonuclari = {}

    # Mevcut sporcu ve tüm önceki sporcu kayıtlarını gez
    mevcut_sporcu = sporcu
    while mevcut_sporcu:
        mevcut_musabakalar = Musabaka.query.join(Katilimci, Musabaka.id == Katilimci.musabaka_id) \
            .filter(Katilimci.sporcu_id == mevcut_sporcu.id).all()
        musabakalar.extend(mevcut_musabakalar)

        # Sonuçları al
        for musabaka in mevcut_musabakalar:
            sonuclar = SporDaliSonuc.query.filter_by(musabaka_id=musabaka.id, sporcu_id=mevcut_sporcu.id).all()
            if musabaka.id in sporcu_musabaka_sonuclari:
                sporcu_musabaka_sonuclari[musabaka.id].extend(sonuclar)
            else:
                sporcu_musabaka_sonuclari[musabaka.id] = sonuclar

        mevcut_sporcu = mevcut_sporcu.eski_sporcu

    # Tüm kulüpler ve il temsilcileri listeleri
    kulupler = Kulup.query.all()
    il_temsilcileri = IlTemsilcisi.query.all()

    # Transfer geçmişi verilerini al
    transfer_gecmisi = []
    mevcut_sporcu = sporcu
    while mevcut_sporcu.eski_sporcu_id:
        onceki_sporcu = Sporcu.query.get(mevcut_sporcu.eski_sporcu_id)
        if onceki_sporcu:
            transfer_bilgisi = {
                'transfer_tarihi': mevcut_sporcu.transfer_tarihi,
                'eski_kulup': onceki_sporcu.kulup.kulup_adi if onceki_sporcu.kulup else 'Bilinmiyor',
                'eski_il_temsilcisi': onceki_sporcu.il_temsilcisi.il if onceki_sporcu.il_temsilcisi else 'Bilinmiyor',
                'yeni_kulup': mevcut_sporcu.kulup.kulup_adi if mevcut_sporcu.kulup else 'Bilinmiyor',
                'yeni_il_temsilcisi': mevcut_sporcu.il_temsilcisi.il if mevcut_sporcu.il_temsilcisi else 'Bilinmiyor'
            }
            transfer_gecmisi.append(transfer_bilgisi)
        mevcut_sporcu = onceki_sporcu

    # Eski sporcuya geri dönüp, eski sporcuya yapılan önceki transferleri de alalım
    eski_transfer_gecmisi = []
    for yeni_sporcu in sporcu.yeni_sporcu:
        transfer_bilgisi = {
            'transfer_tarihi': yeni_sporcu.transfer_tarihi,
            'eski_kulup': sporcu.kulup.kulup_adi if sporcu.kulup else 'Bilinmiyor',
            'eski_il_temsilcisi': sporcu.il_temsilcisi.il if sporcu.il_temsilcisi else 'Bilinmiyor',
            'yeni_kulup': yeni_sporcu.kulup.kulup_adi if yeni_sporcu.kulup else 'Bilinmiyor',
            'yeni_il_temsilcisi': yeni_sporcu.il_temsilcisi.il if yeni_sporcu.il_temsilcisi else 'Bilinmiyor'
        }
        eski_transfer_gecmisi.append(transfer_bilgisi)

    # Tüm transfer geçmişlerini birleştirelim
    transfer_gecmisi.extend(eski_transfer_gecmisi)

    return render_template(
        'sporcu_detay.html',
        sporcu=sporcu,
        antrenorler=antrenorler,
        musabakalar=musabakalar,
        musabaka_sonuclari=sporcu_musabaka_sonuclari,
        kulupler=kulupler,
        il_temsilcileri=il_temsilcileri,
        transfer_gecmisi=transfer_gecmisi,  # Transfer geçmişini template'e gönderiyoruz
        title='Sporcu Detay'
    )


@app.route('/sporcu_ekle', methods=['GET', 'POST'])
@login_required
def sporcu_ekle():
    user_role = session.get('role')
    kulup_id_session = session.get('kulup_id') if user_role == 'Kulup' else None
    il_temsilcisi_il = session.get('il_temsilcisi_il') if user_role == 'IlTemsilcisi' else None
    if user_role not in ['Yonetici', 'Kulup', 'IlTemsilcisi']:
        flash("Bu sayfaya erişim yetkiniz yoktur.", "error")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Formdan gelen bilgileri al
        ad_soyad = request.form.get('ad_soyad')
        tc_no = request.form.get('tc_no')
        dogum_tarihi = request.form.get('dogum_tarihi')
        lisans_no = request.form.get('lisans_no')
        cinsiyet = request.form.get('cinsiyet')
        adres = request.form.get('adres')
        il = request.form.get('il')
        telefon = request.form.get('telefon')
        sporcu_tipi = request.form.get('sporcu_tipi')  # 'kulup' veya 'ferdi' olabilir
        foto = request.files['foto']

        # Fotoğraf işleme
        filename = None
        if foto and allowed_file(foto.filename):
            filename = secure_filename(f"sporcu_{tc_no}.{foto.filename.rsplit('.', 1)[1].lower()}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            foto.save(filepath)

        # Doğum tarihi formatı kontrolü
        try:
            dogum_tarihi = datetime.strptime(dogum_tarihi, '%Y-%m-%d')
        except ValueError:
            flash('Geçersiz tarih formatı. Lütfen YIL-AY-GÜN formatında giriniz.', 'error')
            return redirect(url_for('sporcu_ekle'))

        # Sporcu tipine göre ilgili ID'yi ata
        kulup_id = None
        il_temsilcisi_id = None
        if sporcu_tipi == 'kulup':
            kulup_id = kulup_id_session if user_role == 'Kulup' else request.form.get('kulup_id')
        elif sporcu_tipi == 'ferdi':
            # İl temsilcisinin ID'sini 'il' bilgisine göre bul
            il_temsilcisi = IlTemsilcisi.query.filter_by(il=il).first()
            if il_temsilcisi:
                il_temsilcisi_id = il_temsilcisi.id
            else:
                flash('Belirtilen il için il temsilcisi bulunamadı.', 'error')
                return redirect(url_for('sporcu_ekle'))

        # Sporcu nesnesini oluştur
        yeni_sporcu = Sporcu(
            ad_soyad=ad_soyad,
            tc_no=tc_no,
            dogum_tarihi=dogum_tarihi,
            lisans_no=lisans_no,
            cinsiyet=cinsiyet,
            adres=adres,
            il=il,
            telefon=telefon,
            kulup_id=kulup_id,
            il_temsilcisi_id=il_temsilcisi_id,
            foto=filename
        )

        # Veritabanına sporcu ekle
        db.session.add(yeni_sporcu)
        try:
            db.session.commit()
            flash('Sporcu başarıyla eklendi.', 'success')
        except IntegrityError as e:
            db.session.rollback()
            error_info = str(e.__dict__['orig'])
            if 'tc_no' in error_info:
                flash('Girmiş olduğunuz T.C. kimlik numaralı sporcu zaten kayıtlı.', 'error')
            elif 'lisans_no' in error_info:
                flash('Girmiş olduğunuz lisans numaralı sporcu zaten kayıtlı.', 'error')
            else:
                flash('Bir hata oluştu. Lütfen tekrar deneyin.', 'error')
        except Exception as e:
            db.session.rollback()
            flash(f'Sporcu eklenirken bir hata oluştu: {e}', 'error')

        return redirect(url_for('sporcu_listesi'))

    else:
        # Kulüpleri ve il temsilcilerini sorgula
        kulupler = Kulup.query.all()  # Varsayım, gerçek veritabanı sorgunuzdan kulüpleri çekiyor
        il_temsilcileri = IlTemsilcisi.query.all()  # Varsayım, gerçek veritabanı sorgunuzdan il temsilcilerini çekiyor
        return render_template('sporcu_ekle.html', user_role=user_role, kulup_id_session=kulup_id_session,
                               il_temsilcisi_il=il_temsilcisi_il, kulupler=kulupler, il_temsilcileri=il_temsilcileri,
                               title='Sporcu Ekle')


@app.route('/sporcu_guncelle/<int:sporcu_id>', methods=['GET', 'POST'])
@login_required
def sporcu_guncelle(sporcu_id):
    kullanici_id = session.get('user_id')

    # Kullanıcı oturum açmamışsa, giriş yapma sayfasına yönlendir
    if kullanici_id is None:
        flash('Lütfen giriş yapın.', 'danger')
        return redirect(url_for('giris'))  # veya başka bir giriş sayfası

    # Antrenör ve hakem kontrolü
    kullanici_antrenor = Antrenor.query.filter_by(kullanici_id=kullanici_id).first()
    kullanici_hakem = Hakem.query.filter_by(kullanici_id=kullanici_id).first()
    if kullanici_antrenor or kullanici_hakem:
        flash('Antrenörlerin ve hakemlerin bu sayfaya erişim yetkisi yok.', 'danger')
        return redirect(url_for('dashboard'))  # veya başka bir uygun sayfa

    kullanici_id = session.get('user_id')
    sporcu = Sporcu.query.get_or_404(sporcu_id)
    kulupler = Kulup.query.all()
    il_temsilcileri = IlTemsilcisi.query.all()
    kullanici_kulup = Kulup.query.filter_by(kullanici_id=kullanici_id).first()
    kullanici_il_temsilcisi = IlTemsilcisi.query.filter_by(kullanici_id=kullanici_id).first()

    sporcu_tipi = 'kulup' if sporcu.kulup_id else 'ferdi' if sporcu.il_temsilcisi_id else None

    # Erişim kontrolü
    if (kullanici_kulup and sporcu.kulup_id != kullanici_kulup.id) or (
            kullanici_il_temsilcisi and sporcu.il_temsilcisi_id != kullanici_il_temsilcisi.id):
        flash('Bu sporcuyu güncelleme yetkiniz yok.', 'danger')
        return redirect(url_for('sporcu_listesi'))

    if request.method == 'POST':
        # Form verilerini al
        sporcu.ad_soyad = request.form['ad_soyad']
        sporcu.tc_no = request.form['tc_no']
        sporcu.dogum_tarihi = datetime.strptime(request.form['dogum_tarihi'], '%Y-%m-%d')
        sporcu.lisans_no = request.form.get('lisans_no')
        sporcu.cinsiyet = request.form['cinsiyet']
        sporcu.adres = request.form['adres']
        sporcu.il = request.form['il']
        sporcu.telefon = request.form.get('telefon')
        sporcu_tipi = request.form.get('sporcu_tipi')

        if sporcu_tipi == 'kulup':
            sporcu.kulup_id = request.form.get('kulup_id')
            sporcu.il_temsilcisi_id = None
        elif sporcu_tipi == 'ferdi':
            sporcu.il_temsilcisi_id = request.form.get('il_temsilcisi_id')
            sporcu.kulup_id = None

        # Fotoğraf güncelleme işlemleri
        foto = request.files['foto']
        if foto and allowed_file(foto.filename):
            filename = secure_filename(foto.filename)
            foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            foto.save(foto_path)
            sporcu.foto = filename

        # Veritabanı güncelleme işlemleri
        db.session.commit()
        flash('Sporcu başarıyla güncellendi.', 'success')
        return redirect(url_for('sporcu_listesi'))

    # GET isteği için sporcu tipini tekrar tanımlama
    return render_template('sporcu_guncelle.html', sporcu=sporcu, kulupler=kulupler, il_temsilcileri=il_temsilcileri,
                           sporcu_tipi=sporcu_tipi, title='Sporcu Güncelle')


@app.route('/sporcu_sil/<int:sporcu_id>', methods=['POST'])
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def sporcu_sil(sporcu_id):
    sporcu = Sporcu.query.get_or_404(sporcu_id)
    try:
        # Sporcuya bağlı sonuçları sil
        sporcu_sonuclari = SporDaliSonuc.query.filter_by(sporcu_id=sporcu.id).all()
        for sonuc in sporcu_sonuclari:
            db.session.delete(sonuc)

        # Sporcuyu sil
        db.session.delete(sporcu)
        db.session.commit()
        flash('Sporcu ve ilgili sonuçlar başarıyla silindi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Sporcu silinirken bir hata oluştu: {e}', 'error')
    return redirect(url_for('sporcu_listesi'))

def role_required(role):
    def decorator(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            if session.get('role') != role:
                flash('Bu işlem sadece federasyon yöneticileri tarafından yapılabilir.', 'danger')
                return redirect(url_for('sporcu_listesi'))  # Kullanıcıyı sporcu listesi sayfasına yönlendir
            return func(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/sporcu_transfer_et/<int:sporcu_id>', methods=['GET', 'POST'])
@login_required
@role_required('Yonetici')
def sporcu_transfer_et(sporcu_id):
    sporcu = Sporcu.query.get_or_404(sporcu_id)

    if request.method == 'POST':
        yeni_kulup_id = request.form.get('kulup_id')
        yeni_il_temsilcisi_id = request.form.get('il_temsilcisi_id')
        transfer_tarihi = datetime.now()

        # Eski sporcuyu pasif yap ve transfer bilgilerini ekle
        sporcu.aktif = False
        sporcu.transfer_edildi = True
        sporcu.transfer_tarihi = transfer_tarihi

        # TC kimlik numarası ve lisans numarasının başına transfer kodu ekleme
        sporcu.tc_no = f"TES-{sporcu.tc_no}" if sporcu.tc_no else None
        sporcu.lisans_no = f"TES-{sporcu.lisans_no}" if sporcu.lisans_no else None

        db.session.commit()

        # Yeni sporcu oluşturma
        yeni_sporcu = Sporcu(
            ad_soyad=sporcu.ad_soyad,
            tc_no=sporcu.tc_no.replace("TES-", "") if sporcu.tc_no else None,  # Transfer kodunu çıkartıp eski değeri kullanıyoruz
            dogum_tarihi=sporcu.dogum_tarihi,
            lisans_no=sporcu.lisans_no.replace("TES-", "") if sporcu.lisans_no else None,  # Transfer kodunu çıkartıp eski değeri kullanıyoruz
            cinsiyet=sporcu.cinsiyet,
            adres=sporcu.adres,
            il=sporcu.il,
            telefon=sporcu.telefon,
            kulup_id=yeni_kulup_id,
            il_temsilcisi_id=yeni_il_temsilcisi_id,
            foto=sporcu.foto,
            transfer_tarihi=transfer_tarihi,
            eski_sporcu_id=sporcu.id,  # Eski sporcunun ID'si yeni sporcuya atanıyor
            transfer_kulubu_id=yeni_kulup_id,
            transfer_il_temsilcisi_id=yeni_il_temsilcisi_id
        )

        db.session.add(yeni_sporcu)
        db.session.commit()

        flash('Sporcu başarıyla transfer edildi.', 'success')
        return redirect(url_for('sporcu_detay', sporcu_id=yeni_sporcu.id))

    kulupler = Kulup.query.all()
    il_temsilcileri = IlTemsilcisi.query.all()

    return render_template('sporcu_transfer_et.html', sporcu=sporcu, kulupler=kulupler, il_temsilcileri=il_temsilcileri, title='Sporcu Transfer Et')


@app.route('/sporcu/<int:yeni_sporcu_id>/transfer_geri_al', methods=['POST'])
@login_required
@role_required('Yonetici')
def sporcu_transfer_geri_al(yeni_sporcu_id):
    # Yeni sporcu kaydını bul
    yeni_sporcu = Sporcu.query.get_or_404(yeni_sporcu_id)

    # Eski sporcu kaydını bul
    eski_sporcu = Sporcu.query.get_or_404(yeni_sporcu.eski_sporcu_id)

    # Yeni sporcu kaydını sil
    db.session.delete(yeni_sporcu)
    db.session.commit()

    # Eski sporcuyu tekrar aktif yap ve transfer bilgilerini geri al
    eski_sporcu.aktif = True
    eski_sporcu.transfer_edildi = False
    eski_sporcu.transfer_tarihi = None

    # Eski sporcunun TC kimlik numarası ve lisans numarasından TES- kodunu kaldır
    if eski_sporcu.tc_no and eski_sporcu.tc_no.startswith("TES-"):
        eski_sporcu.tc_no = eski_sporcu.tc_no.replace("TES-", "")
    if eski_sporcu.lisans_no and eski_sporcu.lisans_no.startswith("TES-"):
        eski_sporcu.lisans_no = eski_sporcu.lisans_no.replace("TES-", "")

    db.session.commit()

    flash('Transfer geri alındı ve eski sporcu kaydı geri yüklendi.', 'success')
    return redirect(url_for('sporcu_detay', sporcu_id=eski_sporcu.id))


@app.route('/musabaka_listesi')
@login_required
def musabaka_listesi():
    kullanici_id = session.get('user_id')
    kullanici_rol = session.get('role')

    # Eğer kullanıcı Yönetici değilse ve MHK üyesi de değilse, yetki hatası ver.
    if kullanici_rol != 'Yonetici' and not is_mhk_member(kullanici_id):
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    # İşlemi yapacak kullanıcı "Yönetici" veya MHK üyesi ise, işleme devam et
    musabakalar = (
        Musabaka.query
        .options(joinedload(Musabaka.brans))
        .all()
    )
    return render_template('musabaka_listesi.html', musabakalar=musabakalar, title='Müsabaka Listesi')


@app.route('/musabaka_ekle', methods=['GET', 'POST'])
@login_required
def musabaka_ekle():
    kullanici_id = session.get('user_id')
    kullanici_rol = session.get('role')

    # Eğer kullanıcı Yönetici değilse ve MHK üyesi de değilse, yetki hatası ver.
    if kullanici_rol != 'Yonetici' and not is_mhk_member(kullanici_id):
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    # İşlemi yapacak kullanıcı "Yönetici" veya MHK üyesi ise, işleme devam et
    branslar = Brans.query.all()
    yas_kategorileri = YasKategorisi.query.all()

    if request.method == 'POST':
        musabaka_adi = request.form.get('musabaka_adi')
        baslama_tarihi = request.form.get('baslama_tarihi')
        bitis_tarihi = request.form.get('bitis_tarihi')
        il = request.form.get('il')
        katilimci_ekleme_baslangic_tarihi = request.form.get('katilimci_ekleme_baslangic_tarihi')
        katilimci_ekleme_bitis_tarihi = request.form.get('katilimci_ekleme_bitis_tarihi')
        brans_id = request.form.get('brans_id')
        yas_kategori_idler = request.form.getlist('yas_kategori_id[]')

        yeni_musabaka = Musabaka(
            musabaka_adi=musabaka_adi,
            baslama_tarihi=(
                datetime.strptime(baslama_tarihi, '%Y-%m-%d').date()
                if baslama_tarihi else None
            ),
            bitis_tarihi=(
                datetime.strptime(bitis_tarihi, '%Y-%m-%d').date()
                if bitis_tarihi else None
            ),
            il=il,
            katilimci_ekleme_baslangic_tarihi=(
                datetime.strptime(katilimci_ekleme_baslangic_tarihi, '%Y-%m-%d').date()
                if katilimci_ekleme_baslangic_tarihi else None
            ),
            katilimci_ekleme_bitis_tarihi=(
                datetime.strptime(katilimci_ekleme_bitis_tarihi, '%Y-%m-%d').date()
                if katilimci_ekleme_bitis_tarihi else None
            ),
            brans_id=brans_id
        )

        # Yaş kategorilerini ilişkilendir
        for yas_kategori_id in yas_kategori_idler:
            yas_kategori = YasKategorisi.query.get(yas_kategori_id)
            if yas_kategori:
                yeni_musabaka.yas_kategorileri.append(yas_kategori)

        # Veritabanına ekle
        db.session.add(yeni_musabaka)
        try:
            db.session.commit()
            flash('Yeni müsabaka başarıyla eklendi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Müsabaka eklerken bir hata oluştu: {e}', 'error')

        return redirect(url_for('musabaka_listesi'))

    return render_template('musabaka_ekle.html', branslar=branslar, yas_kategorileri=yas_kategorileri,
                           title='Müsabaka Ekle')


@app.route('/musabaka_duzenle/<int:musabaka_id>', methods=['GET', 'POST'])
@login_required
def musabaka_duzenle(musabaka_id):
    musabaka = Musabaka.query.get_or_404(musabaka_id)
    branslar = Brans.query.all()
    yas_kategorileri = YasKategorisi.query.all()
    musabaka_yas_kategori_idleri = [kategori.id for kategori in musabaka.yas_kategorileri]

    # Kullanıcının yetkisini kontrol et
    kullanici_rol = session.get('role')
    if kullanici_rol not in ['Yonetici'] and not is_mhk_member(session.get('user_id')):
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        musabaka_adi = request.form['musabaka_adi']
        baslama_tarihi = request.form['baslama_tarihi']
        bitis_tarihi = request.form['bitis_tarihi']
        il = request.form['il']
        katilimci_ekleme_baslangic_tarihi = request.form['katilimci_ekleme_baslangic_tarihi']
        katilimci_ekleme_bitis_tarihi = request.form['katilimci_ekleme_bitis_tarihi']
        brans_id = request.form['brans_id']
        yas_kategori_idler = request.form.getlist('yas_kategori_id[]')

        musabaka.musabaka_adi = musabaka_adi
        musabaka.baslama_tarihi = datetime.strptime(baslama_tarihi, '%Y-%m-%d').date() if baslama_tarihi else None
        musabaka.bitis_tarihi = datetime.strptime(bitis_tarihi, '%Y-%m-%d').date() if bitis_tarihi else None
        musabaka.il = il
        musabaka.katilimci_ekleme_baslangic_tarihi = datetime.strptime(
            katilimci_ekleme_baslangic_tarihi, '%Y-%m-%d'
        ).date() if katilimci_ekleme_baslangic_tarihi else None
        musabaka.katilimci_ekleme_bitis_tarihi = datetime.strptime(
            katilimci_ekleme_bitis_tarihi, '%Y-%m-%d'
        ).date() if katilimci_ekleme_bitis_tarihi else None
        musabaka.brans_id = brans_id
        musabaka.yas_kategorileri = YasKategorisi.query.filter(
            YasKategorisi.id.in_(yas_kategori_idler)
        ).all()

        try:
            db.session.commit()
            flash('Müsabaka başarıyla güncellendi.', 'success')
            return redirect(url_for('musabaka_listesi'))
        except Exception as e:
            db.session.rollback()
            flash('Bir hata oluştu: ' + str(e), 'error')
            return redirect(url_for('musabaka_listesi'))

    return render_template(
        'musabaka_duzenle.html', title='Müsabaka Düzenle', musabaka=musabaka,
        branslar=branslar, yas_kategorileri=yas_kategorileri,
        musabaka_yas_kategori_idleri=musabaka_yas_kategori_idleri
    )


@app.route('/musabaka_sil/<int:musabaka_id>', methods=['POST'])
@login_required
def musabaka_sil(musabaka_id):
    musabaka = Musabaka.query.get_or_404(musabaka_id)

    kullanici_rol = session.get('role')
    if kullanici_rol not in ['Yonetici'] and not is_mhk_member(session.get('user_id')):
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Müsabaka ile ilişkili hakem görevlendirme taleplerini sil
        HakemGorevlendirmeTalebi.query.filter_by(musabaka_id=musabaka_id).delete()

        # Diğer ilişkili verileri de silmek gerekebilir, örneğin:
        # Katılımcıları sil
        Katilimci.query.filter_by(musabaka_id=musabaka_id).delete()

        db.session.delete(musabaka)
        db.session.commit()
        flash('Müsabaka başarıyla silindi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Müsabaka silinirken bir hata oluştu: {e}', 'danger')

    return redirect(url_for('musabaka_listesi'))


@app.route('/brans_listesi')
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def brans_listesi():
    branslar = Brans.query.all()
    return render_template('brans_listesi.html', branslar=branslar, title='Branş Listesi')


@app.route('/brans_ekle', methods=['GET', 'POST'])
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def brans_ekle():
    spor_dallari = SporDali.query.all()
    sonuc_turleri = SonucTuru.query.all()

    if request.method == 'POST':
        brans_adi = request.form.get('brans_adi')
        secili_spor_dallari = request.form.getlist('spor_dallari')
        secili_sonuc_turleri = request.form.getlist('sonuc_turleri')

        yeni_brans = Brans(brans_adi=brans_adi)

        # Seçilen spor dallarını ilişkilendir
        for dal_id in secili_spor_dallari:
            spor_dali = SporDali.query.get(dal_id)
            yeni_brans.spor_dallari.append(spor_dali)

        # Seçilen sonuç türlerini ilişkilendir
        for tur_id in secili_sonuc_turleri:
            sonuc_turu = SonucTuru.query.get(tur_id)
            yeni_brans.sonuc_turleri.append(sonuc_turu)

        db.session.add(yeni_brans)
        try:
            db.session.commit()
            flash('Yeni branş başarıyla eklendi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Branş eklerken bir hata oluştu: {e}', 'error')

        return redirect(url_for('brans_listesi'))

    return render_template('brans_ekle.html', spor_dallari=spor_dallari, sonuc_turleri=sonuc_turleri, title='Branş Ekle')


@app.route('/brans_duzenle/<int:brans_id>', methods=['GET', 'POST'])
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def brans_duzenle(brans_id):
    brans = Brans.query.get_or_404(brans_id)
    spor_dallari = SporDali.query.all()
    sonuc_turleri = SonucTuru.query.all()

    if request.method == 'POST':
        brans.brans_adi = request.form['brans_adi']
        secili_spor_dallari = request.form.getlist('spor_dallari')
        secili_sonuc_turleri = request.form.getlist('sonuc_turleri')

        # Spor dalları ve sonuç türlerini güncelle
        brans.spor_dallari = [SporDali.query.get(dal_id) for dal_id in secili_spor_dallari]
        brans.sonuc_turleri = [SonucTuru.query.get(tur_id) for tur_id in secili_sonuc_turleri]

        try:
            db.session.commit()
            flash('Branş başarıyla güncellendi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Branş güncellenirken bir hata oluştu: {e}', 'error')

        return redirect(url_for('brans_listesi'))

    secili_dallar = [dal.id for dal in brans.spor_dallari]
    secili_turler = [tur.id for tur in brans.sonuc_turleri]

    return render_template('brans_duzenle.html', brans=brans, spor_dallari=spor_dallari, secili_dallar=secili_dallar, sonuc_turleri=sonuc_turleri, secili_turler=secili_turler, title='Branş Düzenle')


@app.route('/brans_sil/<int:id>', methods=['POST'])
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def brans_sil(id):
    brans = Brans.query.get_or_404(id)
    try:
        db.session.delete(brans)
        db.session.commit()
        flash('Branş başarıyla silindi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Branş silinirken bir hata oluştu: {e}', 'error')
    return redirect(url_for('brans_listesi'))


@app.route('/antrenorler')
@login_required
def antrenor_listesi():
    kullanici_id = session.get('user_id')
    kullanici_rol = session.get('role')

    # Kullanıcı hakem ise erişimi engelle
    if kullanici_rol == 'Hakem':
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))  # Hakemleri başka bir sayfaya yönlendir

    kulup = Kulup.query.filter_by(kullanici_id=kullanici_id).first()

    # Antrenör mü kontrolü
    antrenor = Antrenor.query.filter_by(kullanici_id=kullanici_id).first()
    if antrenor:
        # Antrenör detay sayfasına yönlendirme
        return redirect(url_for('antrenor_detay', antrenor_id=antrenor.id))

    if kulup:
        antrenorler = Antrenor.query.filter_by(kulup_id=kulup.id).all()
    else:
        antrenorler = Antrenor.query.all()

    return render_template('antrenor_listesi.html', antrenor_listesi=antrenorler, title='Antrenör Listesi')


@app.route('/antrenor/<int:antrenor_id>')
@login_required
def antrenor_detay(antrenor_id):
    kullanici_id = session.get('user_id')
    kullanici_rol = session.get('role')
    antrenor = Antrenor.query.get_or_404(antrenor_id)
    kulup = Kulup.query.get_or_404(antrenor.kulup_id)

    # Kullanıcı hakem ise erişimi engelle
    if kullanici_rol == 'Hakem':
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('antrenor_listesi'))

    # Kullanıcının yöneticiliğini kontrol et ve izin ver
    if kullanici_rol == 'Yonetici':
        # Kulübe kayıtlı transfer edilmemiş sporcuların listesini al
        kulup_sporculari = Sporcu.query.filter_by(kulup_id=kulup.id, transfer_edildi=False).all()

        # Antrenörün ilgili olduğu müsabakaların listesini al
        antrenor_musabakalari = Musabaka.query.join(Katilimci).filter(Katilimci.antrenor_id == antrenor.id).all()

        return render_template('antrenor_detay.html', antrenor=antrenor, kulup=kulup, kulup_sporculari=kulup_sporculari,
                               antrenor_musabakalari=antrenor_musabakalari, title='Antrenör Detay')

    # Kullanıcının antrenör olup olmadığını ve o antrenör için yetkisi olup olmadığını kontrol et
    if kullanici_rol == 'Antrenor':
        kullanici_antrenor = Antrenor.query.filter_by(kullanici_id=kullanici_id).first()
        if kullanici_antrenor and kullanici_antrenor.id != antrenor_id:
            flash('Bu antrenörün detaylarına erişim yetkiniz yok.', 'danger')
            return redirect(url_for('antrenor_listesi'))

    # Kullanıcının kulübünü kontrol et ve sadece kendi kulübündeki antrenörler için erişime izin ver
    if kullanici_rol == 'Kulup':
        kullanici_kulup = Kulup.query.filter_by(kullanici_id=kullanici_id).first()
        if kullanici_kulup and kullanici_kulup.id != kulup.id:
            flash('Bu antrenörün detaylarına erişim yetkiniz yok.', 'danger')
            return redirect(url_for('antrenor_listesi'))

    # Kulübe kayıtlı transfer edilmemiş sporcuların listesini al
    kulup_sporculari = Sporcu.query.filter_by(kulup_id=kulup.id, transfer_edildi=False).all()

    # Antrenörün ilgili olduğu müsabakaların listesini al
    antrenor_musabakalari = Musabaka.query.join(Katilimci).filter(Katilimci.antrenor_id == antrenor.id).all()

    return render_template('antrenor_detay.html', antrenor=antrenor, kulup=kulup, kulup_sporculari=kulup_sporculari,
                           antrenor_musabakalari=antrenor_musabakalari, title='Antrenör Detay')



@app.route('/antrenor_ekle', methods=['GET', 'POST'])
@login_required
def antrenor_ekle():
    # Kullanıcının kulüp ID'sini oturumdan al
    kulup_id = session.get('kulup_id')  # Örnek olarak kullanıcıya ait kulüp ID'si oturumda tutuluyor
    kulup_adi = Kulup.query.filter_by(id=kulup_id).first().kulup_adi if kulup_id else None
    # Kullanıcının rolünü kontrol et
    kullanici_rol = session.get('role')
    if kullanici_rol not in ['Yonetici', 'Kulup']:
        flash("Bu sayfaya erişim yetkiniz yoktur.", "error")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Form verilerini al
        tc_kimlik_no = request.form.get('tc_kimlik_no')
        ad_soyad = request.form.get('ad_soyad')
        telefon = request.form.get('telefon')
        eposta = request.form.get('eposta')
        adres = request.form.get('adres')
        kullanici_adi = request.form.get('kullanici_adi')
        sifre = request.form.get('sifre')  # Gerçek uygulamada şifreyi hash'lemek önemlidir
        kulup_id = request.form.get('kulup_id')
        foto = request.files['foto']

        # TC kimlik numarasının benzersizliğini kontrol et
        mevcut_antrenor = Antrenor.query.filter_by(tc_kimlik_no=tc_kimlik_no).first()
        if mevcut_antrenor:
            flash('Bu TC kimlik numarası ile kayıtlı bir antrenör zaten mevcut.', 'error')
            return render_template('antrenor_ekle.html', title='Antrenör Ekle', kulup_adi=kulup_adi, kulup_id=kulup_id)

        # Yeni kullanıcı oluştur
        hashed_sifre = generate_password_hash(sifre, method='pbkdf2:sha256', salt_length=16)
        yeni_kullanici = Kullanici(kullanici_adi=kullanici_adi, sifre=hashed_sifre, rol=Rol.Antrenor, aktif=True)
        db.session.add(yeni_kullanici)

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(str(e), 'danger')
            return render_template('antrenor_ekle.html', title='Antrenör Ekle', kulup_adi=kulup_adi, kulup_id=kulup_id)

        if foto and allowed_file(foto.filename):
            filename = secure_filename(f"antrenor_{tc_kimlik_no}.{foto.filename.rsplit('.', 1)[1].lower()}")
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            foto_dosya_adi = filename
        else:
            foto_dosya_adi = None

        # Yeni antrenör oluştur
        yeni_antrenor = Antrenor(
            tc_kimlik_no=tc_kimlik_no,
            ad_soyad=ad_soyad,
            telefon=telefon,
            eposta=eposta,
            adres=adres,
            kullanici_id=yeni_kullanici.id,
            kulup_id=kulup_id,
            foto=foto_dosya_adi
        )
        db.session.add(yeni_antrenor)

        # Antrenör veritabanına eklenirken hata kontrolü
        try:
            db.session.commit()
            flash('Antrenör başarıyla eklendi.', 'success')
            return redirect(url_for('antrenor_listesi'))
        except Exception as e:
            db.session.rollback()
            flash(str(e), 'danger')

    return render_template('antrenor_ekle.html', kulup_adi=kulup_adi, kulup_id=kulup_id, title='Antrenör Ekle')


# Antrenör düzenleme işlevi
@app.route('/antrenor_duzenle/<int:antrenor_id>', methods=['GET', 'POST'])
@login_required
def antrenor_duzenle(antrenor_id):
    antrenor = Antrenor.query.get_or_404(antrenor_id)
    kulupler = Kulup.query.all()
    kullanici = Kullanici.query.get_or_404(antrenor.kullanici_id)
    session_kullanici_id = session.get('user_id')
    session_kullanici_rol = session.get('role')
    session_kullanici_kulup = Kulup.query.filter_by(kullanici_id=session_kullanici_id).first()

    # Kullanıcının antrenörü veya kendi kulübünü düzenleme yetkisi olup olmadığını kontrol et
    if not (session_kullanici_id == kullanici.id or
            session_kullanici_rol == 'Yonetici' or
            (session_kullanici_kulup and session_kullanici_kulup.id == antrenor.kulup_id)):
        flash('Bu antrenörü güncellemeye erişim yetkiniz yok.', 'danger')
        return redirect(url_for('antrenor_listesi'))

    if request.method == 'POST':
        # Form verilerini al
        antrenor.tc_kimlik_no = request.form.get('tc_kimlik_no')
        antrenor.ad_soyad = request.form.get('ad_soyad')
        antrenor.telefon = request.form.get('telefon')
        antrenor.eposta = request.form.get('eposta')
        antrenor.adres = request.form.get('adres')
        antrenor.kulup_id = request.form.get('kulup_id')

        foto = request.files['foto']
        if foto and allowed_file(foto.filename):
            filename = secure_filename(f"antrenor_{antrenor.tc_kimlik_no}.{foto.filename.rsplit('.', 1)[1].lower()}")
            foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            foto.save(foto_path)
            antrenor.foto = filename  # Sadece dosya adını güncelle

        # Veritabanını güncelle
        db.session.commit()
        flash('Antrenör başarıyla güncellendi.', 'success')
        return redirect(url_for('antrenor_listesi'))

    # GET isteği veya hata durumları için antrenör bilgileriyle formu doldur
    return render_template('antrenor_duzenle.html', session_kullanici_rol=session.get('role'), antrenor=antrenor, kullanici=kullanici, kulupler=kulupler,
                           title='Antrenör Düzenle')


@app.route('/antrenor_sil/<int:id>', methods=['POST'])
@login_required
@check_permission('Yonetici')
def antrenor_sil(id):
    # Antrenörü bul
    antrenor = Antrenor.query.get_or_404(id)
    try:
        # Antrenör fotoğrafını silmek için gerekirse burada kodlarınız olacak
        if antrenor.foto:
            eski_foto_path = os.path.join(app.config['UPLOAD_FOLDER'], antrenor.foto)
            if os.path.isfile(eski_foto_path):
                os.remove(eski_foto_path)

        # İlgili kullanıcıyı bul
        kullanici = Kullanici.query.get(antrenor.kullanici_id)

        if kullanici:
            # Kullanıcıya bağlı geçmiş kayıtları sil
            kullanici_gecmis = KullaniciGecmis.query.filter_by(kullanici_id=kullanici.id).all()
            for gecmis in kullanici_gecmis:
                db.session.delete(gecmis)

            # Kullanıcıya bağlı şifre sıfırlama tokenlarını sil
            sifre_tokenlari = SifreSifirlamaToken.query.filter_by(kullanici_id=kullanici.id).all()
            for token in sifre_tokenlari:
                db.session.delete(token)

            # Kullanıcıyı sil
            db.session.delete(kullanici)

        # Antrenörü sil
        db.session.delete(antrenor)

        db.session.commit()
        flash('Antrenör ve ilişkili kullanıcı başarıyla silindi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Antrenör ve ilişkili kullanıcı silinirken bir hata oluştu: ' + str(e), 'danger')

    return redirect(url_for('antrenor_listesi'))


@app.route('/hakem-listesi')
@login_required
def hakem_listesi():
    kullanici_id = session.get('user_id')
    kullanici_rol = session.get('role')

    # Kullanıcının hakem olup olmadığını ve MHK üyesi olup olmadığını kontrol et
    kullanici_hakem = Hakem.query.filter_by(kullanici_id=kullanici_id).first()

    # Yönetici veya MHK üyesi hakemler hakem listesine erişebilir
    if kullanici_rol == 'Yonetici' or (kullanici_hakem and kullanici_hakem.mhk_uyesi_mi):
        hakemler = Hakem.query.join(Kullanici).add_columns(
            Hakem.id, Hakem.foto, Hakem.ad_soyad, Hakem.tc_kimlik_no,
            Hakem.derece, Hakem.telefon, Hakem.eposta, Hakem.il,
            Kullanici.kullanici_adi
        ).all()
        musabakalar = Musabaka.query.all()
        return render_template('hakem_listesi.html', hakemler=hakemler, musabakalar=musabakalar, title='Hakem Listesi')

    # Sadece "normal" hakemler kendi detay sayfalarına yönlendirilir
    elif kullanici_hakem and not kullanici_hakem.mhk_uyesi_mi:
        return redirect(url_for('hakem_detay', hakem_id=kullanici_hakem.id))

    # Diğer durumlar için erişim yetkisi yok uyarısı
    else:
        flash('Bu sayfaya erişim yetkiniz bulunmamaktadır.', 'error')
        return redirect(url_for('dashboard'))


@app.route('/hakem-detay/<int:hakem_id>', methods=['GET'])
@login_required
def hakem_detay(hakem_id):
    kullanici_id = session.get('user_id')
    kullanici_rol = session.get('role')

    # Kullanıcıya ait hakemi ve diğer bilgileri al
    kullanici_hakem = Hakem.query.filter_by(kullanici_id=kullanici_id).first()
    hakem = Hakem.query.get_or_404(hakem_id)
    hakem_belgeleri = HakemBelge.query.filter_by(hakem_id=hakem_id).all()
    belge_tipleri = [tip.value for tip in BelgeTipi]

    # MHK üyesi olup olmadığını kontrol et
    mhk_uyesi_mi = is_mhk_member(kullanici_id)

    # Erişim kontrolü ve şablonu render etme
    if kullanici_rol == 'Yonetici' or (kullanici_hakem and kullanici_hakem.id == hakem_id) or mhk_uyesi_mi:
        # MHK üyesi veya yönetici veya hakemi kullanıcıya aitse hakem detaylarına erişim yetkisi var
        return render_template('hakem_detay.html', hakem=hakem,
                               hakem_musabakalar=hakem.musabakalar,
                               hakem_belgeleri=hakem_belgeleri,
                               belge_tipleri=belge_tipleri,
                               kullanici_id=kullanici_id,
                               mhk_uyesi_mi=mhk_uyesi_mi,  # Bu değişkeni şablona geçir
                               title='Hakem Detay')
    else:
        # Hakem detaylarına erişim yetkisi yok
        flash('Bu hakemin detaylarına erişim yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/mhk_uyesi_durumu_degistir/<int:hakem_id>', methods=['GET', 'POST'])
def mhk_uyesi_durumu_degistir(hakem_id):
    hakem = Hakem.query.get_or_404(hakem_id)
    hakem.mhk_uyesi_mi = not hakem.mhk_uyesi_mi
    db.session.commit()
    flash('MHK üyeliği durumu başarıyla güncellendi.', 'success')
    return redirect(url_for('hakem_detay', hakem_id=hakem_id))


@app.route('/hakem-belge-yukle/<int:hakem_id>', methods=['POST'])
@login_required
def hakem_belge_yukle(hakem_id):
    hakem = Hakem.query.get_or_404(hakem_id)
    belge_tipi = request.form.get('belge_tipi')
    belge_dosyasi = request.files.get('file')

    if belge_dosyasi and allowed_file(belge_dosyasi.filename, file_type='document'):
        dosya_uzantisi = belge_dosyasi.filename.rsplit('.', 1)[1].lower()
        yeni_dosya_adi = f"hakem_{hakem.tc_kimlik_no}_{belge_tipi.replace(' ', '_')}.{dosya_uzantisi}"
        save_path = os.path.join(app.config['BELGE_UPLOAD_FOLDER'], yeni_dosya_adi)

        try:
            belge_dosyasi.save(save_path)
            yeni_belge = HakemBelge(hakem_id=hakem_id, belge_tipi=belge_tipi, belge_yolu=yeni_dosya_adi)
            db.session.add(yeni_belge)
            db.session.commit()
            flash('Belge başarıyla yüklendi.', 'success')
        except Exception as e:
            print("Dosya kaydetme sırasında hata:", e)
            flash('Dosya yüklenirken bir hata oluştu.', 'danger')

    return redirect(url_for('hakem_detay', hakem_id=hakem_id))


@app.route('/belge-sil/<int:hakem_id>/<int:belge_id>')
@login_required
def belge_sil(hakem_id, belge_id):
    # Erişim kontrolü
    if not_yetkili_kullanici(hakem_id):
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    belge = HakemBelge.query.get_or_404(belge_id)
    if belge.hakem_id != hakem_id:
        flash('Geçersiz işlem.', 'danger')
        return redirect(url_for('hakem_detay', hakem_id=hakem_id))

    # Dosyayı sil
    dosya_yolu = os.path.join(app.static_folder, belge.belge_yolu)
    if os.path.exists(dosya_yolu):
        os.remove(dosya_yolu)

    # Veritabanından belgeyi sil
    db.session.delete(belge)
    db.session.commit()

    flash('Belge başarıyla silindi.', 'success')
    return redirect(url_for('hakem_detay', hakem_id=hakem_id))


@app.route('/hakem_ekle', methods=['GET', 'POST'])
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def hakem_ekle():
    if request.method == 'POST':
        # Form verilerini al
        ad_soyad = request.form.get('ad_soyad')
        tc_kimlik_no = request.form.get('tc_kimlik_no')
        derece = request.form.get('derece')  # Doğrudan formdan alınan string değer
        telefon = request.form.get('telefon')
        eposta = request.form.get('eposta')
        adres = request.form.get('adres')
        izin_adresi = request.form.get('izin_adresi')
        iban = request.form.get('iban')
        dogum_tarihi_str = request.form.get('dogum_tarihi')
        hakem_ili = request.form.get('hakem_ili')
        kutuk_no = request.form.get('kutuk_no')
        kullanici_adi = request.form.get('kullanici_adi')
        sifre = request.form.get('sifre')
        foto = request.files['foto']

        # dogum_tarihi_str'yi bir Python date nesnesine dönüştür
        try:
            dogum_tarihi = datetime.strptime(dogum_tarihi_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Geçersiz tarih formatı. Yıl-Ay-Gün formatını kullanın.', 'error')
            return redirect(request.url)

        # Yeni kullanıcı oluştur
        hashed_sifre = generate_password_hash(sifre, 'pbkdf2:sha256', 16)
        yeni_kullanici = Kullanici(kullanici_adi=kullanici_adi, sifre=hashed_sifre, rol=Rol.Hakem, aktif=True)
        db.session.add(yeni_kullanici)

        # Kullanıcı veritabanına eklenirken hata kontrolü
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(str(e), 'danger')
            return render_template('hakem_ekle.html')

        # Fotoğrafın dosya adını oluştur ve kaydet
        foto_dosya_adi = None
        if foto and allowed_file(foto.filename):
            filename = secure_filename(f"hakem_{tc_kimlik_no}.{foto.filename.rsplit('.', 1)[1].lower()}")
            foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            foto.save(foto_path)
            foto_dosya_adi = filename

        # Yeni hakem oluştur
        yeni_hakem = Hakem(
            ad_soyad=ad_soyad,
            tc_kimlik_no=tc_kimlik_no,
            derece=derece,
            telefon=telefon,
            eposta=eposta,
            adres=adres,
            izin_adresi=izin_adresi,
            iban=iban,
            dogum_tarihi=dogum_tarihi,
            il=hakem_ili,
            kutuk_no=kutuk_no,
            kullanici_id=yeni_kullanici.id,
            foto=foto_dosya_adi
        )
        db.session.add(yeni_hakem)

        # Hakem veritabanına eklenirken hata kontrolü
        try:
            db.session.commit()
            flash('Hakem başarıyla eklendi.', 'success')
            return redirect(url_for('hakem_listesi'))
        except Exception as e:
            db.session.rollback()
            flash(str(e), 'danger')

    return render_template('hakem_ekle.html', title='Hakem Ekle')


def format_date(value, date_format='%Y-%m-%d'):
    if value is None:
        return ""
    return value.strftime(date_format)


# Jinja2 ortamınıza bu filtre fonksiyonunu ekleyin
app.jinja_env.filters['date'] = format_date


@app.route('/hakem_duzenle/<int:hakem_id>', methods=['GET', 'POST'])
@login_required
def hakem_duzenle(hakem_id):
    hakem = Hakem.query.get_or_404(hakem_id)
    kullanici = Kullanici.query.get_or_404(hakem.kullanici_id)

    # Erişim kontrolü
    if not (session.get('user_id') == kullanici.id or session.get('role') == 'Yonetici' or is_mhk_member(session.get('user_id'))):
        flash('Bu sayfayı görüntüleme yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Form verilerini al
        hakem.ad_soyad = request.form.get('ad_soyad')
        hakem.tc_kimlik_no = request.form.get('tc_kimlik_no')
        hakem.derece = request.form.get('derece')
        hakem.telefon = request.form.get('telefon')
        hakem.eposta = request.form.get('eposta')
        hakem.adres = request.form.get('adres')
        hakem.izin_adresi = request.form.get('izin_adresi')
        hakem.iban = request.form.get('iban')
        dogum_tarihi_str = request.form.get('dogum_tarihi')
        hakem.il = request.form.get('hakem_ili')
        hakem.kutuk_no = request.form.get('kutuk_no')

        # dogum_tarihi'yi güncelle
        try:
            hakem.dogum_tarihi = datetime.strptime(dogum_tarihi_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Geçersiz tarih formatı. Yıl-Ay-Gün formatını kullanın.', 'error')
            return redirect(request.url)

        # Fotoğrafı kontrol et ve güncelle
        foto = request.files['foto']
        if foto and allowed_file(foto.filename, 'image'):
            filename = secure_filename(f"hakem_{hakem.tc_kimlik_no}.{foto.filename.rsplit('.', 1)[1].lower()}")
            foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            foto.save(foto_path)
            hakem.foto = filename  # Hakemin fotoğrafını güncelle

        yeni_sifre = request.form.get('yeni_sifre')
        if yeni_sifre:
            kullanici.sifre = generate_password_hash(yeni_sifre)

        # Belgeleri işleme
        belge_listesi = request.files.getlist('belge')
        belge_sayisi = HakemBelge.query.filter_by(hakem_id=hakem.id).count()  # Mevcut belge sayısını al

        for belge in belge_listesi:
            if belge and allowed_file(belge.filename, 'document'):
                belge_sayisi += 1
                belge_uzantisi = belge.filename.rsplit('.', 1)[1]  # Dosya uzantısını al
                belge_filename = f"{hakem.tc_kimlik_no}_belge{belge_sayisi}.{belge_uzantisi}"
                belge_klasoru = os.path.join(app.static_folder, 'hakembelge')
                os.makedirs(belge_klasoru, exist_ok=True)
                belge_path = os.path.join(belge_klasoru, belge_filename)
                belge.save(belge_path)

                # Veritabanına kaydedilecek göreli yol
                goreli_belge_yolu = os.path.join('hakembelge', belge_filename).replace('\\', '/')

                # Yeni belgeyi veritabanına ekle
                yeni_belge = HakemBelge(hakem_id=hakem.id, belge_yolu=goreli_belge_yolu)
                db.session.add(yeni_belge)

        # Veritabanı güncellemelerini yap
        try:
            db.session.commit()
            flash('Hakem ve kullanıcı bilgileri başarıyla güncellendi!', 'success')
            return redirect(url_for('hakem_detay', hakem_id=hakem_id))
        except Exception as e:
            db.session.rollback()
            flash(str(e), 'danger')
            return redirect(request.url)

    # GET isteği için formu doldur
    return render_template('hakem_duzenle.html', hakem=hakem, kullanici_adi=kullanici.kullanici_adi, title='Hakem Düzenle')


@app.route('/hakem_sil/<int:hakem_id>', methods=['POST'])
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def hakem_sil(hakem_id):
    # Hakemi veritabanından bul
    hakem = Hakem.query.get_or_404(hakem_id)
    kullanici_id = hakem.kullanici_id

    # Hakemi veritabanından sil
    db.session.delete(hakem)

    # İlgili Kullanıcıyı veritabanından bul
    kullanici = Kullanici.query.get(kullanici_id)
    if kullanici:
        # Kullanıcıyı veritabanından sil
        db.session.delete(kullanici)

    # Değişiklikleri veritabanına uygula
    try:
        db.session.commit()
        flash('Hakem ve ilişkili kullanıcı başarıyla silindi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(str(e), 'danger')

    return redirect(url_for('hakem_listesi'))


@app.route('/hakem_gorevlendir', methods=['POST'])
@login_required
def hakem_gorevlendir():
    kullanici_id = session.get('user_id')
    kullanici_rol = session.get('role')

    if kullanici_rol != 'Yonetici' and not is_mhk_member(kullanici_id):
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    hakem_id = request.form.get('hakem_id')
    musabaka_id = request.form.get('musabaka_id')

    # Görevlendirme olup olmadığını kontrol et
    var_mi = db.session.query(musabaka_hakem).filter_by(
        hakem_id=hakem_id,
        musabaka_id=musabaka_id
    ).first()

    if var_mi:
        flash('Hakem zaten bu müsabakaya görevlendirilmiş.', 'error')
        return redirect(url_for('gorevlendirme_talepleri'))

    # Yeni bir görevlendirme ekle
    yeni_gorevlendirme = musabaka_hakem.insert().values(
        hakem_id=hakem_id,
        musabaka_id=musabaka_id
    )
    db.session.execute(yeni_gorevlendirme)
    db.session.commit()

    flash('Görevlendirme başarılı.', 'success')
    return redirect(url_for('gorevlendirme_talepleri'))


@app.route('/hakem_gorevden_kaldir/<int:musabaka_id>/<int:hakem_id>', methods=['POST'])
@login_required
def hakem_gorevden_kaldir(musabaka_id, hakem_id):
    # Kullanıcının yetkisini kontrol et
    kullanici_rol = session.get('role')
    if kullanici_rol != 'Yonetici' and not is_mhk_member(session.get('user_id')):
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    # İlişkili görevlendirme kaydını bul ve sil
    gorevlendirme = musabaka_hakem.delete().where(
        (musabaka_hakem.c.hakem_id == hakem_id) &
        (musabaka_hakem.c.musabaka_id == musabaka_id)
    )
    db.session.execute(gorevlendirme)
    db.session.commit()

    # İlgili hakem talep kaydını "Görevden Kaldırıldı" olarak güncelle
    talep = HakemGorevlendirmeTalebi.query.filter_by(hakem_id=hakem_id, musabaka_id=musabaka_id).first()
    if talep:
        talep.durum = GorevlendirmeDurumu.GOREVDEN_KALDIRILDI
        db.session.commit()

    flash('Hakem görevden alındı ve talep durumu güncellendi.', 'success')
    return redirect(url_for('gorevli_hakemler', musabaka_id=musabaka_id))


@app.route('/gorevlendirme_talepleri')
@login_required
def gorevlendirme_talepleri():
    kullanici_rol = session.get('role')
    if kullanici_rol != 'Yonetici' and not is_mhk_member(session.get('user_id')):
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    talepler = HakemGorevlendirmeTalebi.query.filter_by(durum=GorevlendirmeDurumu.BEKLEMEDE).all()
    return render_template('gorevlendirme_talepleri.html', talepler=talepler)


@app.route('/gorevlendirme_talebi_onayla/<int:talep_id>', methods=['POST'])
@login_required
def gorevlendirme_talebi_onayla(talep_id):
    talep = HakemGorevlendirmeTalebi.query.get_or_404(talep_id)
    if talep.durum != GorevlendirmeDurumu.BEKLEMEDE:
        flash('Bu talep zaten işleme alınmış.', 'warning')
        return redirect(url_for('gorevlendirme_talepleri_listesi'))

    # Hakemin bu müsabaka için zaten atanıp atanmadığını kontrol et
    mevcut_gorevlendirme = db.session.execute(
        musabaka_hakem.select().where(
            musabaka_hakem.c.musabaka_id == talep.musabaka_id,
            musabaka_hakem.c.hakem_id == talep.hakem_id
        )
    ).first()

    if mevcut_gorevlendirme:
        flash('Bu hakem zaten bu müsabaka için atanmış.', 'warning')
        return redirect(url_for('gorevlendirme_talepleri_listesi'))

    # Yeni görevlendirme kaydı oluştur
    yeni_gorevlendirme = musabaka_hakem.insert().values(
        musabaka_id=talep.musabaka_id,
        hakem_id=talep.hakem_id,
        gorevlendirme_tarihi=func.current_date()
    )

    db.session.execute(yeni_gorevlendirme)
    talep.durum = GorevlendirmeDurumu.ONAYLANDI

    try:
        db.session.commit()
        flash('Görevlendirme talebi onaylandı ve hakem görevlendirildi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Görevlendirme işlemi sırasında bir hata oluştu: {e}', 'danger')

    return redirect(url_for('gorevlendirme_talepleri'))


@app.route('/gorevlendirme_talebi_reddet/<int:talep_id>', methods=['POST'])
@login_required
def gorevlendirme_talebi_reddet(talep_id):
    kullanici_rol = session.get('role')
    if kullanici_rol != 'Yonetici' and not is_mhk_member(session.get('user_id')):
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    talep = HakemGorevlendirmeTalebi.query.get_or_404(talep_id)
    red_sebebi = request.form.get('red_sebebi')
    talep.durum = GorevlendirmeDurumu.REDDEDILDI
    talep.red_sebebi = red_sebebi
    db.session.commit()

    flash('Görevlendirme talebi reddedildi.', 'success')
    return redirect(url_for('gorevlendirme_talepleri'))


@app.route('/gorevli-hakemler/<int:musabaka_id>')
@login_required
def gorevli_hakemler(musabaka_id):
    kullanici_id = session.get('user_id')
    kullanici_rol = session.get('role')

    # Kullanıcının yetkisini kontrol et
    if kullanici_rol != 'Yonetici' and not is_mhk_member(kullanici_id):
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    # Müsabakayı ve hakemleri al
    musabaka = Musabaka.query.get_or_404(musabaka_id)
    hakemler = musabaka.hakemler  # Musabakaya atanmış hakemlerin listesi

    # Hakemlerin listesini konsolda kontrol etme (debugging için)
    print(f"Hakemler: {hakemler}")

    # Görevli hakemleri listeleme sayfasını render et
    return render_template('gorevli_hakemler.html', hakemler=hakemler, musabaka=musabaka, title='Görevli Hakemler')


@app.route('/hakem_gorev_talep_et', methods=['GET', 'POST'])
@login_required
def hakem_gorev_talep_et():
    if request.method == 'POST':
        # Formdan gelen verileri al
        musabaka_id = request.form.get('musabaka_id')
        kullanici_id = session.get('user_id')

        # Kullanıcıya ait hakemi bul
        hakem = Hakem.query.filter_by(kullanici_id=kullanici_id).first()

        if not hakem or not hakem.id:
            flash('Hakem bilgileri bulunamadı.', 'danger')
            return redirect(url_for('dashboard'))

        # Daha önce bu müsabakaya talep oluşturulmuş mu kontrol et
        var_mi = HakemGorevlendirmeTalebi.query.filter_by(hakem_id=hakem.id, musabaka_id=musabaka_id).first()
        if var_mi:
            flash('Bu müsabaka için zaten bir talep oluşturdunuz.', 'error')
            return redirect(url_for('hakem_gorev_talep_et'))

        # Yeni bir görevlendirme talebi oluştur
        yeni_talep = HakemGorevlendirmeTalebi(
            hakem_id=hakem.id,
            musabaka_id=musabaka_id,
            talep_tarihi=datetime.now(timezone.utc),
            durum=GorevlendirmeDurumu.BEKLEMEDE
        )
        db.session.add(yeni_talep)
        db.session.commit()

        flash('Görevlendirme talebiniz oluşturuldu.', 'success')
        return redirect(url_for('hakem_talep_durumu'))

    # Sadece kayıt başlangıç tarihinden itibaren bitiş tarihine kadar olan müsabakaları al
    today = datetime.now().date()
    musabakalar = Musabaka.query.filter(
        Musabaka.katilimci_ekleme_baslangic_tarihi <= today,
        Musabaka.bitis_tarihi >= today
    ).all()

    return render_template('hakem_gorev_talep_et.html', musabakalar=musabakalar)


@app.route('/hakem_talep_durumu', methods=['GET'])
@login_required
def hakem_talep_durumu():
    # Oturumdaki kullanıcı ID'sini al
    kullanici_id = session.get('user_id')

    # Kullanıcıya ait hakemi bul
    hakem = Hakem.query.filter_by(kullanici_id=kullanici_id).first()

    # Eğer hakem bulunamazsa veya ID'si yoksa, hata mesajı göster
    if not hakem or not hakem.id:
        flash('Hakem bilgileri bulunamadı.', 'danger')
        return redirect(url_for('dashboard'))

    # Hakemin yaptığı talepleri al
    talepler = HakemGorevlendirmeTalebi.query.filter_by(hakem_id=hakem.id).all()
    return render_template('hakem_talep_durumu.html', talepler=talepler)


@app.route('/talep_geri_cek/<int:talep_id>', methods=['POST'])
@login_required
def talep_geri_cek(talep_id):
    # Oturumdaki kullanıcı ID'sini al
    kullanici_id = session.get('user_id')

    # Kullanıcıya ait hakemi bul
    hakem = Hakem.query.filter_by(kullanici_id=kullanici_id).first()

    if not hakem or not hakem.id:
        flash('Hakem bilgileri bulunamadı.', 'danger')
        return redirect(url_for('dashboard'))

    # Talebi al
    talep = HakemGorevlendirmeTalebi.query.filter_by(id=talep_id, hakem_id=hakem.id).first()
    if not talep:
        flash('Görev talebi bulunamadı veya silme yetkiniz yok.', 'danger')
        return redirect(url_for('hakem_talep_durumu'))

    try:
        db.session.delete(talep)
        db.session.commit()
        flash('Görev talebiniz geri çekildi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Talep geri çekilirken bir hata oluştu: {str(e)}', 'danger')

    return redirect(url_for('hakem_talep_durumu'))


@app.route('/hakem_gorev_alinan_musabakalar', methods=['GET'])
@login_required
def hakem_gorev_alinan_musabakalar():
    # Oturumdaki kullanıcı ID'sini al
    kullanici_id = session.get('user_id')

    # Kullanıcıya ait hakemi bul
    hakem = Hakem.query.filter_by(kullanici_id=kullanici_id).first()

    # Eğer hakem bulunamazsa veya ID'si yoksa, hata mesajı göster
    if not hakem or not hakem.id:
        flash('Hakem bilgileri bulunamadı.', 'danger')
        return redirect(url_for('dashboard'))

    # Hakemin onaylanmış ve görev aldığı müsabakalar
    gorevli_musabakalar = Musabaka.query.join(musabaka_hakem).filter(musabaka_hakem.c.hakem_id == hakem.id).all()
    return render_template('hakem_gorev_alinan_musabakalar.html', musabakalar=gorevli_musabakalar)


@app.route('/musabaka_katilim')
@login_required
def musabaka_katilim():
    today = date.today()  # Bugünün tarihi

    # Tüm kullanıcılar için tüm müsabakaları çek
    musabakalar = Musabaka.query.all()

    return render_template('musabaka_katilim.html', musabakalar=musabakalar, today=today, title='Müsabaka Katılım')


@app.route('/musabaka/<int:musabaka_id>/sporcu_katilim')
@login_required
def sporcu_katilim(musabaka_id):
    musabaka = Musabaka.query.get_or_404(musabaka_id)
    today = date.today()
    role = session.get('role')

    if role != 'Yonetici':
        if not (musabaka.katilimci_ekleme_baslangic_tarihi <= today <= musabaka.katilimci_ekleme_bitis_tarihi):
            flash('Bu müsabaka şu anda aktif değil.', 'danger')
            return redirect(url_for('dashboard'))

    kullanici_id = session.get('user_id')
    antrenor = Antrenor.query.filter_by(kullanici_id=kullanici_id).first()
    kulup = Kulup.query.filter_by(kullanici_id=kullanici_id).first() if not antrenor else Kulup.query.filter_by(id=antrenor.kulup_id).first()
    il_temsilcisi = IlTemsilcisi.query.filter_by(kullanici_id=kullanici_id).first() if not antrenor else None

    sporcular = []
    eklenen_sporcular = []
    eklenen_sporcular_ids = []

    if role == 'Yonetici':
        sporcular = Sporcu.query.filter_by(transfer_edildi=False).all()  # Tüm sporcuları getir ama transfer edilmeyenleri filtrele
        eklenen_sporcular = Katilimci.query.filter_by(musabaka_id=musabaka_id, antrenor_id=None).all()
        eklenen_sporcular_ids = [katilimci.sporcu_id for katilimci in eklenen_sporcular]
    else:
        if kulup:
            sporcular = Sporcu.query.filter_by(kulup_id=kulup.id, transfer_edildi=False).all()  # Sadece transfer edilmeyen sporcuları getir
        elif il_temsilcisi:
            sporcular = Sporcu.query.filter_by(il_temsilcisi_id=il_temsilcisi.id, transfer_edildi=False).all()  # Sadece transfer edilmeyen sporcuları getir

        eklenen_sporcular = Katilimci.query.filter(
            Katilimci.musabaka_id == musabaka_id,
            Katilimci.sporcu_id.in_([sporcu.id for sporcu in sporcular]),
            Katilimci.antrenor_id.is_(None)  # Sadece sporcuları al
        ).all()
        eklenen_sporcular_ids = [katilimci.sporcu_id for katilimci in eklenen_sporcular]

    # Sadece eklenmemiş ve transfer edilmemiş sporcuları listeleyin
    gosterilecek_sporcular = [sporcu for sporcu in sporcular if sporcu.id not in eklenen_sporcular_ids]

    return render_template('sporcu_katilim.html', sporcular=gosterilecek_sporcular, eklenen_sporcular=eklenen_sporcular,
                           eklenen_sporcular_ids=eklenen_sporcular_ids, musabaka=musabaka, title='Sporcu Katılım')



@app.route('/musabaka/<int:musabaka_id>/update_kategori', methods=['POST'])
@login_required
def update_kategori(musabaka_id):
    sporcu_id = request.form.get('sporcu_id')
    yas_kategori_id = request.form.get('yas_kategori_id')
    derece = request.form.get('derece')  # Derece bilgisini alıyoruz

    # Katılımcıyı güncelle
    katilimci = Katilimci.query.filter_by(musabaka_id=musabaka_id, sporcu_id=sporcu_id).first()
    if katilimci:
        katilimci.yas_kategori_id = yas_kategori_id
        katilimci.derece = derece  # Dereceyi güncelliyoruz
        db.session.commit()
        return "Kategori güncellendi", 200
    return "Kategori güncellenemedi", 400


def ekle_sporcu(sporcu_id, musabaka_id, yas_kategori_id, derece):
    try:
        # Sporcu katılımını ekle
        yeni_katilimci = Katilimci(
            sporcu_id=sporcu_id,
            musabaka_id=musabaka_id,
            yas_kategori_id=yas_kategori_id,
            derece=derece  # Dereceyi burada kaydediyoruz
        )
        db.session.add(yeni_katilimci)
        db.session.commit()

        # Başarılı işlem sonrası mesaj
        flash('Sporcu başarıyla eklendi.', 'success')

    except Exception as e:
        db.session.rollback()
        flash('Sporcu eklenirken bir hata oluştu: {}'.format(str(e)), 'error')

    return redirect(url_for('katilim_listesi', musabaka_id=musabaka_id))


@app.route('/musabaka/<int:musabaka_id>/ekle_sporcu', methods=['POST'])
@login_required
def ekle_sporcu_musabaka(musabaka_id):
    sporcu_id = request.form.get('sporcu_id')
    yas_kategori_id = request.form.get('yas_kategori_id')
    derece = request.form.get(f'sporcu_derece_{sporcu_id}')  # Derece bilgisini alıyoruz
    role = session.get('role')

    # Check if the athlete is already added to the competition
    existing_katilimci = Katilimci.query.filter_by(sporcu_id=sporcu_id, musabaka_id=musabaka_id).first()
    if existing_katilimci:
        # Flash a message to the user
        flash('Bu sporcu zaten müsabakaya eklenmiş.', 'error')
        return redirect(url_for('sporcu_katilim', musabaka_id=musabaka_id))

    # Kullanıcıya ait sporcu kontrolü
    kullanici_id = session.get('user_id')
    antrenor = Antrenor.query.filter_by(kullanici_id=kullanici_id).first()
    kulup = Kulup.query.filter_by(kullanici_id=kullanici_id).first() if not antrenor else Kulup.query.filter_by(id=antrenor.kulup_id).first()
    il_temsilcisi = IlTemsilcisi.query.filter_by(kullanici_id=kullanici_id).first() if not antrenor else None

    if role != 'Yonetici':
        if kulup:
            sporcu = Sporcu.query.filter_by(id=sporcu_id, kulup_id=kulup.id).first()
        elif il_temsilcisi:
            sporcu = Sporcu.query.filter_by(id=sporcu_id, il_temsilcisi_id=il_temsilcisi.id).first()
        else:
            sporcu = None
        if not sporcu:
            flash('Bu sporcu size ait değil.', 'error')
            return redirect(url_for('sporcu_katilim', musabaka_id=musabaka_id))

    # Sporcu eklenirken yaş kategorisi ve derece kontrolü yaparak ekle_sporcu fonksiyonunu çağır
    try:
        ekle_sporcu(sporcu_id, musabaka_id, yas_kategori_id, derece)  # Dereceyi de burada gönderiyoruz
    except ValueError as e:
        flash(str(e), 'error')

    return redirect(url_for('katilim_listesi', musabaka_id=musabaka_id))


@app.route('/musabaka/<int:musabaka_id>/toplu_ekle_sporcu', methods=['POST'])
@login_required
def ekle_toplu_sporcu_musabaka(musabaka_id):
    sporcu_ids = request.form.getlist('sporcu_ids')
    yas_kategori_id = request.form.get('yas_kategori_id')
    role = session.get('role')

    if not sporcu_ids:
        flash('Lütfen en az bir sporcu seçin.', 'error')
        return redirect(url_for('sporcu_katilim', musabaka_id=musabaka_id))

    kullanici_id = session.get('user_id')
    antrenor = Antrenor.query.filter_by(kullanici_id=kullanici_id).first()
    kulup = Kulup.query.filter_by(kullanici_id=kullanici_id).first() if not antrenor else Kulup.query.filter_by(
        id=antrenor.kulup_id).first()
    il_temsilcisi = IlTemsilcisi.query.filter_by(kullanici_id=kullanici_id).first() if not antrenor else None

    for sporcu_id in sporcu_ids:
        if kulup:
            sporcu = Sporcu.query.filter_by(id=sporcu_id, kulup_id=kulup.id).first()
        elif il_temsilcisi:
            sporcu = Sporcu.query.filter_by(id=sporcu_id, il_temsilcisi_id=il_temsilcisi.id).first()
        else:
            sporcu = None

        if role != 'Yonetici' and not sporcu:
            continue

        if sporcu or role == 'Yonetici':
            existing_katilimci = Katilimci.query.filter_by(sporcu_id=sporcu_id, musabaka_id=musabaka_id).first()
            if existing_katilimci:
                continue

            # Derece bilgisini alın
            derece = request.form.get(f'derece')  # Dereceyi alıyoruz

            yeni_katilimci = Katilimci(
                sporcu_id=sporcu_id,
                musabaka_id=musabaka_id,
                yas_kategori_id=yas_kategori_id,
                derece=derece  # Derece bilgisini burada kaydediyoruz
            )
            db.session.add(yeni_katilimci)

    try:
        db.session.commit()
        flash('Sporcular başarıyla eklendi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Sporcular eklenirken bir hata oluştu: {}'.format(str(e)), 'error')

    return redirect(url_for('sporcu_katilim', musabaka_id=musabaka_id))


@app.route('/musabaka/<int:musabaka_id>/toplu_cikar_sporcu', methods=['POST'])
@login_required
def cikar_toplu_sporcu_musabaka(musabaka_id):
    sporcu_ids = request.form.getlist('sporcu_ids')
    role = session.get('role')

    if not sporcu_ids:
        flash('Lütfen en az bir sporcu seçin.', 'error')
        return redirect(url_for('sporcu_katilim', musabaka_id=musabaka_id))

    kullanici_id = session.get('user_id')
    antrenor = Antrenor.query.filter_by(kullanici_id=kullanici_id).first()
    kulup = Kulup.query.filter_by(kullanici_id=kullanici_id).first() if not antrenor else Kulup.query.filter_by(id=antrenor.kulup_id).first()
    il_temsilcisi = IlTemsilcisi.query.filter_by(kullanici_id=kullanici_id).first() if not antrenor else None

    for sporcu_id in sporcu_ids:
        sporcu = None
        if kulup:
            sporcu = Sporcu.query.filter_by(id=sporcu_id, kulup_id=kulup.id).first()
        elif il_temsilcisi:
            sporcu = Sporcu.query.filter_by(id=sporcu_id, il_temsilcisi_id=il_temsilcisi.id).first()

        if role == 'Yonetici' or sporcu:
            katilimci = Katilimci.query.filter_by(sporcu_id=sporcu_id, musabaka_id=musabaka_id).first()
            if katilimci:
                try:
                    db.session.delete(katilimci)
                    db.session.commit()
                    flash(f'Sporcu ID: {sporcu_id} başarıyla çıkarıldı.', 'success')
                except Exception as e:
                    db.session.rollback()
                    flash(f'Sporcu ID: {sporcu_id} çıkarılırken bir hata oluştu: {str(e)}', 'error')
            else:
                flash(f'Sporcu ID: {sporcu_id} için katılımcı bulunamadı.', 'error')
        else:
            flash(f'Sporcu ID: {sporcu_id} için yetkiniz yok.', 'error')

    return redirect(url_for('sporcu_katilim', musabaka_id=musabaka_id))



@app.route('/musabaka/<int:musabaka_id>/antrenor_katilim')
@login_required
def antrenor_katilim(musabaka_id):
    musabaka = Musabaka.query.get_or_404(musabaka_id)
    today = date.today()
    role = session.get('role')  # Oturumdan kullanıcının rolünü al

    # Yönetici için müsabakanın aktif olup olmadığını kontrol etmeyi atla
    if role != 'Yonetici':
        if not (musabaka.katilimci_ekleme_baslangic_tarihi <= today <= musabaka.katilimci_ekleme_bitis_tarihi):
            flash('Bu müsabaka şu anda aktif değil.', 'danger')
            return redirect(url_for('dashboard'))

    kullanici_id = session.get('user_id')

    # Eğer kullanıcı bir kulüp ile ilişkilendirilmişse, sadece o kulübün antrenörlerini getir
    kulup = Kulup.query.filter_by(kullanici_id=kullanici_id).first()
    antrenorler = []
    if kulup:
        antrenorler = Antrenor.query.filter_by(kulup_id=kulup.id).all()
    else:
        # Kullanıcı ne bir kulüp ile ilişkilendirilmiş ne de yönetici değilse, tüm antrenörleri getir
        antrenorler = Antrenor.query.all()

    return render_template('antrenor_katilim.html', antrenorler=antrenorler, musabaka=musabaka,
                           title='Antrenör Katılım')


# Antrenörü müsabakaya ekleyen rota
@app.route('/musabaka/<int:musabaka_id>/ekle_antrenor', methods=['POST'])
@login_required
def ekle_antrenor(musabaka_id):
    antrenor_id = request.form.get('antrenor_id')

    # Check if the coach is already added to the competition
    existing_katilimci = Katilimci.query.filter_by(antrenor_id=antrenor_id, musabaka_id=musabaka_id).first()
    if existing_katilimci:
        # Flash a message to the user
        flash('Bu antrenör zaten müsabakaya eklenmiş.', 'error')
        return redirect(url_for('antrenor_katilim', musabaka_id=musabaka_id))

    # Yeni katılım oluştur ve veritabanına ekle
    yeni_katilimci = Katilimci(antrenor_id=antrenor_id, musabaka_id=musabaka_id)
    db.session.add(yeni_katilimci)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash('Antrenör eklenirken bir hata oluştu: {}'.format(str(e)), 'error')
        return redirect(url_for('antrenor_katilim', musabaka_id=musabaka_id))

    # Flash a success message to the user
    flash('Antrenör başarıyla eklendi.', 'success')
    return redirect(url_for('katilim_listesi', musabaka_id=musabaka_id))


@app.route('/musabaka/<int:musabaka_id>/katilim_listesi')
@login_required
def katilim_listesi(musabaka_id):
    musabaka = db.session.get(Musabaka, musabaka_id)
    today = date.today()

    kullanici_id = session.get('user_id')
    kullanici = db.session.get(Kullanici, kullanici_id)

    antrenor = Antrenor.query.filter_by(kullanici_id=kullanici_id).first()
    kulup = Kulup.query.filter_by(kullanici_id=kullanici_id).first() if not antrenor else db.session.get(Kulup, antrenor.kulup_id)
    il_temsilcisi = IlTemsilcisi.query.filter_by(kullanici_id=kullanici_id).first() if not antrenor else None

    katilimci_sporcular = []
    katilimci_antrenorler = []

    if kulup:
        katilimci_sporcular = Katilimci.query \
            .join(Sporcu, Katilimci.sporcu_id == Sporcu.id) \
            .options(joinedload(Katilimci.sporcu)) \
            .filter(Katilimci.musabaka_id == musabaka_id, Sporcu.kulup_id == kulup.id) \
            .all()
        katilimci_antrenorler = Katilimci.query \
            .join(Antrenor, Katilimci.antrenor_id == Antrenor.id) \
            .filter(Katilimci.musabaka_id == musabaka_id, Antrenor.kulup_id == kulup.id) \
            .all()
    elif il_temsilcisi:
        katilimci_sporcular = Katilimci.query \
            .join(Sporcu, Katilimci.sporcu_id == Sporcu.id) \
            .options(joinedload(Katilimci.sporcu)) \
            .filter(Katilimci.musabaka_id == musabaka_id, Sporcu.il_temsilcisi_id == il_temsilcisi.id) \
            .all()
    else:
        katilimci_sporcular = Katilimci.query \
            .options(joinedload(Katilimci.sporcu)) \
            .filter_by(musabaka_id=musabaka_id, antrenor_id=None) \
            .all()
        katilimci_antrenorler = Katilimci.query \
            .filter_by(musabaka_id=musabaka_id, sporcu_id=None) \
            .all()

    yas_kategorileri = musabaka.yas_kategorileri

    return render_template('katilimcilari_listele.html',
                           title='Kontrol Listesi',
                           katilimci_sporcular=katilimci_sporcular,
                           katilimci_antrenorler=katilimci_antrenorler,
                           musabaka=musabaka,
                           yas_kategorileri=yas_kategorileri,
                           today=today)


@app.route('/katilimci/<int:katilimci_id>/guncelle_kategori', methods=['POST'])
@login_required
def update_category(katilimci_id):
    yeni_yas_kategori_id = request.form.get('yas_kategori_id')
    yeni_derece = request.form.get('derece')  # Derece formdan alınır
    musabaka_id = request.form.get('musabaka_id')  # musabaka_id formdan alınır

    if not yeni_yas_kategori_id:
        flash('Lütfen geçerli bir yaş kategorisi seçin.', 'warning')
        return redirect(url_for('katilim_listesi', musabaka_id=musabaka_id))

    katilimci = db.session.get(Katilimci, katilimci_id)  # Katilimci'yi almak için güncellenmiş kullanım
    yeni_yas_kategori = db.session.get(YasKategorisi,
                                       yeni_yas_kategori_id)  # YasKategorisi'ni almak için güncellenmiş kullanım

    katilimci.yas_kategori_id = yeni_yas_kategori.id

    if yeni_derece:
        katilimci.derece = yeni_derece  # Derece güncellenir

    db.session.commit()
    flash(f'{katilimci.sporcu.ad_soyad} için yaş kategorisi ve derece başarıyla güncellendi.', 'success')
    return redirect(url_for('katilim_listesi', musabaka_id=musabaka_id))


@app.route('/musabaka/<int:musabaka_id>/cikart/<int:katilimci_id>', methods=['POST'])
@login_required
def musabakadan_cikart(musabaka_id, katilimci_id):
    katilimci = Katilimci.query.get_or_404(katilimci_id)
    if katilimci.musabaka_id != musabaka_id:
        # Eğer katılımcı bu müsabaka için değilse, hata mesajı ver
        flash('Bu katılımcı bu müsabakaya ait değil.', 'danger')
        return redirect(url_for('katilim_listesi', musabaka_id=musabaka_id))

    db.session.delete(katilimci)
    db.session.commit()
    flash('Katılımcı müsabakadan başarıyla çıkarıldı.', 'success')
    return redirect(url_for('katilim_listesi', musabaka_id=musabaka_id))


@app.route('/toggle_start_listesi/<int:musabaka_id>')
@login_required
def toggle_start_listesi(musabaka_id):
    musabaka = Musabaka.query.get_or_404(musabaka_id)
    musabaka.start_listesi_aktif = not musabaka.start_listesi_aktif
    db.session.commit()
    flash('Start listesi durumu güncellendi.', 'success')
    return redirect(url_for('musabaka_listesi'))


@app.route('/start_listesi')
@login_required
def start_listesi():
    user_id = session.get('user_id')
    role = session.get('role')

    # Sadece yöneticilerin ve MHK üyelerinin erişimini sağlamak için kontrol
    if role != 'Yonetici' and not is_mhk_member(user_id):
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(request.referrer or url_for('home'))  # Önceki sayfaya yönlendir, yoksa ana sayfa

    aktif_musabakalar = Musabaka.query.order_by(Musabaka.id.desc()).all()

    secili_musabaka_id = request.args.get('musabaka_id', type=int) or (
        aktif_musabakalar[0].id if aktif_musabakalar else None)

    secili_musabaka = None
    if secili_musabaka_id:
        secili_musabaka = db.session.get(Musabaka, secili_musabaka_id)

    if not secili_musabaka:
        flash('Aktif müsabaka bulunamadı.', 'warning')
        return render_template('start_listesi.html', aktif_musabakalar=aktif_musabakalar)

    katilimcilar = Katilimci.query.join(Sporcu).filter(Katilimci.musabaka_id == secili_musabaka_id).all()
    gruplanmis_katilimcilar = defaultdict(lambda: defaultdict(list))

    for katilimci in katilimcilar:
        derece = katilimci.derece if katilimci.derece else '99:99:99'
        try:
            dakika, saniye, salise = map(int, derece.split(':'))
            derece_seconds = 60 * dakika + saniye + salise / 1000.0
        except (ValueError, TypeError):
            derece_seconds = float('inf')

        katilimci.derece_seconds = derece_seconds
        gruplanmis_katilimcilar[katilimci.yas_kategori.yas_kategori_adi][katilimci.sporcu.cinsiyet].append(katilimci)

    def siralama_anahtari(katilimci):
        derece_seconds = katilimci.derece_seconds
        if derece_seconds == float('inf'):
            return (0, derece_seconds)  # No Time olanlar en üstte
        else:
            return (1, -derece_seconds)  # Süre bilgisi olanlar yavaştan hızlıya doğru

    yas_kategori_siralama = ["U9", "U11", "U13", "U15", "U17", "U19", "GENÇLER", "BÜYÜKLER", "MASTER +30", "MASTER +40",
                             "MASTER +50", "MASTER +60", "MASTER +70", "MASTER +80"]
    cinsiyet_siralama = ["Kadın", "Erkek"]

    siralanmis_katilimcilar = defaultdict(lambda: defaultdict(list))
    for yas_kategori in yas_kategori_siralama:
        for cinsiyet in cinsiyet_siralama:
            if gruplanmis_katilimcilar[yas_kategori][cinsiyet]:
                gruplanmis_katilimcilar[yas_kategori][cinsiyet].sort(key=siralama_anahtari)
                siralanmis_katilimcilar[yas_kategori][cinsiyet] = gruplanmis_katilimcilar[yas_kategori][cinsiyet]

    return render_template('start_listesi.html', aktif_musabakalar=aktif_musabakalar, secili_musabaka=secili_musabaka,
                           gruplanmis_katilimcilar=siralanmis_katilimcilar)



@app.route('/kontrol_listesi')
def kontrol_listesi():
    role = session.get('role')

    # Yönetici ve diğer kullanıcılar için aktif müsabakaları al
    if role == 'Yonetici':
        aktif_musabakalar = Musabaka.query.order_by(Musabaka.id.desc()).all()
    else:
        aktif_musabakalar = Musabaka.query.filter_by(start_listesi_aktif=True).order_by(Musabaka.id.desc()).all()

    # Seçili müsabakayı al ve kontrol et
    secili_musabaka_id = request.args.get('musabaka_id', type=int) or (
        aktif_musabakalar[0].id if aktif_musabakalar else None)
    secili_musabaka = Musabaka.query.filter_by(id=secili_musabaka_id).first() if secili_musabaka_id else None

    # Eğer yönetici değilse ve müsabaka aktif değilse, uyarı göster
    if role != 'Yonetici' and (secili_musabaka is None or not secili_musabaka.start_listesi_aktif):
        flash('Bu müsabaka için Kontrol listesi henüz yayınlanmadı.', 'warning')
        return redirect(url_for('tum_musabakalar'))

    # Katılımcıları al ve grupla
    katilimcilar = Katilimci.query.join(Sporcu).filter(Katilimci.musabaka_id == secili_musabaka_id).all()
    gruplanmis_katilimcilar = defaultdict(lambda: defaultdict(list))

    for katilimci in katilimcilar:
        try:
            if katilimci.derece:  # Derece None değilse işlem yap
                # Dereceyi 'MM:SS:SSS' formatından saniyeye çevir
                dakika, saniye, salise = map(int, katilimci.derece.split(':'))
                derece_seconds = 60 * dakika + saniye + salise / 1000.0  # Saliseleri saniyeye çevir
            else:
                # Derece None ise büyük bir değer kullan
                derece_seconds = float('inf')
        except (ValueError, TypeError):
            # Hatalı format durumunda büyük bir değer kullan
            derece_seconds = float('inf')

        katilimci.derece_seconds = derece_seconds
        gruplanmis_katilimcilar[katilimci.yas_kategori.yas_kategori_adi][katilimci.sporcu.cinsiyet].append(katilimci)

    # Yaş kategorileri ve cinsiyetler için sıralama listesi
    yas_kategori_siralama = [
        "U9", "U11", "U13", "U15", "U17", "U19", "GENÇLER", "BÜYÜKLER",
        "MASTER +30", "MASTER +40", "MASTER +50", "MASTER +60",
        "MASTER +70", "MASTER +80"
    ]
    cinsiyet_siralama = ["Kadın", "Erkek"]

    # Sıralama fonksiyonu
    def siralama_anahtari(katilimci):
        derece_seconds = katilimci.derece_seconds
        if derece_seconds == float('inf'):
            return 0, derece_seconds  # Derecesi olmayanlar en üste
        else:
            return 1, -derece_seconds  # Derecesi olanlar, en yüksekten en düşüğe

    # Sıralama listesine göre sporcuları sırala
    siralanmis_katilimcilar = defaultdict(lambda: defaultdict(list))
    for yas_kategori in yas_kategori_siralama:
        for cinsiyet in cinsiyet_siralama:
            if gruplanmis_katilimcilar[yas_kategori][cinsiyet]:
                gruplanmis_katilimcilar[yas_kategori][cinsiyet].sort(key=siralama_anahtari)
                siralanmis_katilimcilar[yas_kategori][cinsiyet] = gruplanmis_katilimcilar[yas_kategori][cinsiyet]

    # Render şablonu ve verileri geç
    return render_template('kontrol_listesi.html', aktif_musabakalar=aktif_musabakalar, secili_musabaka=secili_musabaka,
                           gruplanmis_katilimcilar=siralanmis_katilimcilar)


@app.route('/download_file/<int:musabaka_id>')
def download_file(musabaka_id):
    secili_musabaka = Musabaka.query.get(musabaka_id)
    if secili_musabaka is None:
        flash('İlgili dosya bulunamadı.', 'danger')
        return redirect(url_for('kontrol_listesi'))

    # Dosya yolunu dinamik olarak belirleyin
    file_path = f'path/to/files/{secili_musabaka.dosya_adi}'  # Örnek: path/to/files/musabaka_9_start_listesi.pdf

    try:
        return send_file(
            file_path,
            as_attachment=True,
            download_name=f'{secili_musabaka.musabaka_adi}_start_listesi.pdf'  # Dosya indirme adı
        )
    except FileNotFoundError:
        flash('Dosya bulunamadı.', 'danger')
        return redirect(url_for('kontrol_listesi'))


@app.route('/export_to_excel/<int:musabaka_id>')
@login_required
def export_to_excel(musabaka_id):
    musabaka = Musabaka.query.get_or_404(musabaka_id)
    katilimcilar = Katilimci.query.filter_by(musabaka_id=musabaka.id).all()

    yas_kategori_siralama = [
        "U9", "U11", "U13", "U15", "U17", "U19", "GENÇLER", "BÜYÜKLER",
        "MASTER +30", "MASTER +40", "MASTER +50", "MASTER +60",
        "MASTER +70", "MASTER +80"
    ]
    cinsiyet_siralama = ["Kadın", "Erkek"]

    gruplanmis_katilimcilar = defaultdict(lambda: defaultdict(list))
    for katilimci in katilimcilar:
        yas_kategori = katilimci.yas_kategori.yas_kategori_adi if katilimci.yas_kategori else 'Diğer'
        cinsiyet = katilimci.sporcu.cinsiyet if katilimci.sporcu else 'Bilinmiyor'
        if yas_kategori in yas_kategori_siralama and cinsiyet in cinsiyet_siralama:
            gruplanmis_katilimcilar[yas_kategori][cinsiyet].append(katilimci)

    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    title_format = workbook.add_format({'bold': True, 'font_size': 14, 'align': 'center', 'valign': 'vcenter'})

    left_logo_path = 'static/images/gsblogo.png'
    right_logo_path = 'static/images/tmpflogo.png'

    def siralama_anahtari(katilimci):
        derece = katilimci.derece if katilimci.derece else '99:99:99'
        try:
            dakika, saniye, salise = map(int, derece.split(':'))
            derece_seconds = 60 * dakika + saniye + salise / 1000.0
            return 1, -derece_seconds  # Süre bilgisi olanlar yavaştan hızlıya doğru sıralanır
        except (ValueError, TypeError):
            return 0, 0  # Derecesi olmayanlar en üstte yer alır

    for yas_kategori in yas_kategori_siralama:
        for cinsiyet in cinsiyet_siralama:
            katilimcilar = gruplanmis_katilimcilar[yas_kategori][cinsiyet]
            if katilimcilar:
                katilimcilar.sort(key=siralama_anahtari)
                worksheet = workbook.add_worksheet(f"{yas_kategori} {cinsiyet}"[:31])
                worksheet.merge_range('B1:F1', 'TÜRKİYE MODERN PENTATLON FEDERASYONU', title_format)
                worksheet.merge_range('B2:F2', musabaka.musabaka_adi, title_format)
                worksheet.merge_range('B3:F3', f"Başlama Tarihi: {musabaka.baslama_tarihi.strftime('%d.%m.%Y')}",
                                      title_format)
                worksheet.merge_range('B4:F4', f"Bitiş Tarihi: {musabaka.bitis_tarihi.strftime('%d.%m.%Y')}",
                                      title_format)
                worksheet.merge_range('B5:F5', f"İl: {musabaka.il}", title_format)
                worksheet.merge_range('B6:F6', f"Kategori: {yas_kategori} {cinsiyet}", title_format)

                worksheet.insert_image('A1', left_logo_path,
                                       {'x_offset': 15, 'y_offset': 10, 'x_scale': 0.8, 'y_scale': 0.7})
                worksheet.insert_image('G1', right_logo_path,
                                       {'x_offset': 15, 'y_offset': 10, 'x_scale': 1, 'y_scale': 0.9})

                headers = ['Sıra', 'Ad Soyad', 'Doğum Yılı', 'Cinsiyet', 'Kulübü/İli', 'Derece']
                worksheet.write_row('A7', headers, title_format)

                for index, katilimci in enumerate(katilimcilar, start=1):
                    kulup_veya_il = (katilimci.sporcu.kulup.kulup_adi
                                     if katilimci.sporcu and katilimci.sporcu.kulup else
                                     f"{katilimci.sporcu.il} Ferdi Sporcu"
                                     if katilimci.sporcu else 'Bilinmiyor')
                    ad_soyad = (katilimci.sporcu.ad_soyad.upper()
                                if katilimci.sporcu and katilimci.sporcu.ad_soyad else 'Bilinmiyor')
                    row = [
                        index,
                        ad_soyad,
                        katilimci.sporcu.dogum_tarihi.strftime(
                            '%Y') if katilimci.sporcu and katilimci.sporcu.dogum_tarihi else 'Bilinmiyor',
                        katilimci.sporcu.cinsiyet if katilimci.sporcu else 'Bilinmiyor',
                        kulup_veya_il,
                        katilimci.derece if katilimci.derece else 'No Time'
                    ]
                    worksheet.write_row(f'A{index + 7}', row)

    workbook.close()
    output.seek(0)

    return send_file(
        output,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=f"musabaka_{musabaka_id}.xlsx"
    )


@app.route('/duyurular')
@login_required
def duyurular():
    tum_duyurular = Duyuru.query.order_by(Duyuru.yayinlanma_tarihi.desc()).all()
    duyurular_ve_yazarlar = []

    for duyuru in tum_duyurular:
        # UTC tarih ve saati yerel saate dönüştür
        duyuru.yayinlanma_tarihi = convert_utc_to_local(duyuru.yayinlanma_tarihi)

        yonetici = Yonetici.query.filter_by(kullanici_id=duyuru.yazar_id).first()
        yazar_ad_soyad = yonetici.ad_soyad if yonetici else "Bilinmeyen Yazar"
        duyurular_ve_yazarlar.append((duyuru, yazar_ad_soyad))

    return render_template('duyurular.html', duyurular_ve_yazarlar=duyurular_ve_yazarlar, title='Duyurular')


@app.route('/duyuru_ekle', methods=['GET', 'POST'])
@login_required
@check_permission('Yonetici')  # Sadece yöneticilerin erişimine izin ver
def duyuru_ekle():
    if request.method == 'POST':
        baslik = request.form.get('baslik')
        icerik = request.form.get('icerik')
        yeni_duyuru = Duyuru(baslik=baslik, icerik=icerik, yazar_id=session['user_id'])
        db.session.add(yeni_duyuru)
        db.session.commit()
        flash('Duyuru başarıyla eklendi.', 'success')
        return redirect(url_for('duyurular'))

    return render_template('duyuru_ekle.html')


@app.route('/duyuru_detay/<int:duyuru_id>')
@login_required
def duyuru_detay(duyuru_id):
    duyuru = Duyuru.query.get_or_404(duyuru_id)
    yonetici = Yonetici.query.filter_by(kullanici_id=duyuru.yazar_id).first()
    yazar_ad_soyad = yonetici.ad_soyad if yonetici else "Bilinmeyen Yazar"
    return render_template('duyuru_detay.html', duyuru=duyuru, yazar_ad_soyad=yazar_ad_soyad, title='Duyuru Detay')


@app.route('/duyuru_guncelle/<int:duyuru_id>', methods=['GET', 'POST'])
@login_required
@check_permission('Yonetici')
def duyuru_guncelle(duyuru_id):
    duyuru = Duyuru.query.get_or_404(duyuru_id)

    if request.method == 'POST':
        duyuru.baslik = request.form.get('baslik')
        duyuru.icerik = request.form.get('icerik')
        db.session.commit()
        flash('Duyuru başarıyla güncellendi.', 'success')
        return redirect(url_for('duyurular'))

    return render_template('duyuru_guncelle.html', duyuru=duyuru)


@app.route('/duyuru_sil/<int:duyuru_id>', methods=['POST'])
@login_required
@check_permission('Yonetici')
def duyuru_sil(duyuru_id):
    duyuru = Duyuru.query.get_or_404(duyuru_id)
    db.session.delete(duyuru)
    db.session.commit()
    flash('Duyuru başarıyla silindi.', 'success')
    return redirect(url_for('duyurular'))


@app.route('/hakem_basvuru', methods=['GET', 'POST'])
def hakem_basvuru():
    if not app.config['BASVURULAR_ACIK']:
        # Başvurular kapalıysa uyarı mesajı göster
        flash('Şu anda hakem başvuruları kabul edilmemektedir.', 'info')
        return render_template('basvurular_kapali.html')  # Özel bir şablon gösterebilirsiniz
    if request.method == 'POST':
        try:
            # Form verilerini al
            ad_soyad = request.form['ad_soyad']
            kutuk_no = request.form.get('kutuk_no', '')
            dogum_tarihi = datetime.strptime(request.form['dogum_tarihi'], '%Y-%m-%d')
            telefon = request.form['telefon']
            eposta = request.form['eposta']
            iban = request.form['iban']
            adres = request.form['adres']
            il = request.form['il']
            izin_adresi = request.form.get('izin_adresi', '')
            tc_kimlik_no = request.form['tc_kimlik_no']
            if not re.match(r'^\d{11}$', tc_kimlik_no):
                flash('Geçersiz TC Kimlik Numarası', 'danger')
                return redirect(url_for('hatali_basvuru'))

            # TC kimlik numarası kontrolü
            existing_basvuru = HakemBasvuru.query.filter_by(tc_kimlik_no=tc_kimlik_no).first()
            if existing_basvuru:
                flash('Girmiş olduğunuz TC kimlik numarası daha önce kayıt yapmıştır.', 'danger')
                return redirect(url_for('hakem_basvuru'))

            # Fotoğraf yükleme
            foto = request.files['foto']
            foto_filename = None
            if foto and allowed_file(foto.filename, 'image'):
                foto_filename = secure_filename(f"{tc_kimlik_no}_foto.{foto.filename.rsplit('.', 1)[1].lower()}")
                foto.save(os.path.join(app.config['HAKEM_ADAY_UPLOAD_FOLDER'], foto_filename))

            # Hakem başvurusu kaydı
            basvuru = HakemBasvuru(
                ad_soyad=ad_soyad,
                tc_kimlik_no=tc_kimlik_no,
                kutuk_no=kutuk_no,
                dogum_tarihi=dogum_tarihi,
                telefon=telefon,
                eposta=eposta,
                iban=iban,
                adres=adres,
                il=il,
                izin_adresi=izin_adresi,
                foto=foto_filename
            )
            db.session.add(basvuru)
            db.session.flush()

            # Belgelerin kaydı
            belge_listesi = [
                'cezasi_yoktur_belgesi',
                'ogrenim_belgesi',
                'nufus_cuzdani_fotokopisi',
                'adli_sicil_kaydi',
                'saglik_raporu',
                'dekont'
            ]
            for belge_adi in belge_listesi:
                belge = request.files.get(belge_adi)
                if belge and allowed_file(belge.filename, 'document'):
                    belge_filename = secure_filename(
                        f"{tc_kimlik_no}_{belge_adi}.{belge.filename.rsplit('.', 1)[1].lower()}")
                    belge.save(os.path.join(app.config['HAKEM_ADAY_UPLOAD_FOLDER'], belge_filename))
                    belge_basvuru = HakemBelgeBasvuru(
                        basvuru_id=basvuru.id,
                        belge_tipi=belge_adi,
                        belge_yolu=belge_filename
                    )
                    db.session.add(belge_basvuru)

            db.session.commit()
            flash('Başvurunuz başarıyla alındı ve inceleme sürecindedir.', 'success')
            return redirect(url_for('basarili_basvuru'))

        except Exception as e:
            db.session.rollback()
            flash(str(e), 'danger')
            return redirect(url_for('hatali_basvuru'))

    return render_template('hakem_basvuru.html')


@app.route('/basarili_basvuru')
def basarili_basvuru():
    return render_template('basarili_basvuru.html')


@app.route('/hatali_basvuru')
def hatali_basvuru():
    return render_template('hatali_basvuru.html')


@app.route('/hakem_basvuru_listesi', methods=['GET'])
@login_required
def hakem_basvuru_listesi():
    kullanici_id = session.get('user_id')
    kullanici_rol = session.get('role')

    # Eğer kullanıcı Yönetici değilse ve MHK üyesi de değilse, yetki hatası ver.
    if kullanici_rol != 'Yonetici' and not is_mhk_member(kullanici_id):
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    # İşlemi yapacak kullanıcı "Yönetici" veya MHK üyesi ise, işleme devam et
    hakem_basvurulari = HakemBasvuru.query.all()
    print(hakem_basvurulari)  # Bu satır, hakem_basvurulari değişkeninin içeriğini yazdıracaktır.
    return render_template('hakem_basvuru_listesi.html', hakem_basvurulari=hakem_basvurulari)


@app.route('/hakem_basvuru_detay/<int:id>', methods=['GET'])
@login_required
@check_permission('Yonetici')  # 'Yonetici' rolüne sahip kullanıcılara erişim izni ver
def hakem_basvuru_detay(id):
    # Veritabanından belirli bir hakem başvurusunu çekin (id ile belirtilir)
    hakem_basvuru = db.session.get(HakemBasvuru, id)

    if hakem_basvuru is None:
        flash('Belirtilen hakem başvurusu bulunamadı', 'danger')
        return redirect(url_for('hakem_basvuru_listesi'))

    return render_template('hakem_basvuru_detay.html', hakem_basvuru=hakem_basvuru)


@app.route('/hakem_basvuru_sil/<int:id>', methods=['POST'])
@login_required
@check_permission('Yonetici')
def hakem_basvuru_sil(id):
    hakem_basvuru = db.session.get(HakemBasvuru, id)

    if hakem_basvuru is None:
        flash('Belirtilen hakem başvurusu bulunamadı', 'danger')
        return redirect(url_for('hakem_basvuru_listesi'))

    try:
        # Başvuruyu ve belgeleri sil
        hakem_basvuru.delete_with_belgeler()

        flash('Hakem başvurusu ve belgeleri başarıyla silindi', 'success')
    except Exception as e:
        flash(f'Hata: Başvuru ve belgeleri silinemedi - {str(e)}', 'danger')

    return redirect(url_for('hakem_basvuru_listesi'))


@app.route('/hakem_basvuru_onayla/<int:basvuru_id>', methods=['POST'])
@login_required
@check_permission('Yonetici')
def hakem_basvuru_onayla(basvuru_id):
    basvuru = HakemBasvuru.query.get(basvuru_id)
    if not basvuru:
        flash('Hakem başvurusu bulunamadı', 'danger')
        return redirect(url_for('hakem_basvuru_listesi'))

    try:
        tc_kimlik_no = basvuru.tc_kimlik_no
        hashed_sifre = generate_password_hash(tc_kimlik_no, 'pbkdf2:sha256', 16)

        yeni_kullanici = Kullanici(
            kullanici_adi=tc_kimlik_no,
            sifre=hashed_sifre,
            rol=Rol.Hakem,
            aktif=True
        )
        db.session.add(yeni_kullanici)
        db.session.flush()

        # Fotoğrafı taşı ve yeniden adlandır
        eski_foto_yolu = os.path.join(current_app.config['HAKEM_ADAY_UPLOAD_FOLDER'], basvuru.foto)
        yeni_foto_adi = f"hakem_{tc_kimlik_no}.jpg"
        yeni_foto_yolu = os.path.join(current_app.config['UPLOAD_FOLDER'], yeni_foto_adi)
        if os.path.exists(eski_foto_yolu):
            shutil.move(str(eski_foto_yolu), str(yeni_foto_yolu))

        # Hakem oluştur
        yeni_hakem = Hakem(
            ad_soyad=basvuru.ad_soyad,
            tc_kimlik_no=tc_kimlik_no,
            derece='Aday Hakem',
            telefon=basvuru.telefon,
            eposta=basvuru.eposta,
            adres=basvuru.adres,
            izin_adresi=basvuru.izin_adresi,
            iban=basvuru.iban,
            dogum_tarihi=basvuru.dogum_tarihi,
            il=basvuru.il,
            kutuk_no=tc_kimlik_no,
            kullanici_id=yeni_kullanici.id,
            foto=yeni_foto_adi
        )
        db.session.add(yeni_hakem)
        db.session.flush()

        # Belgeleri taşı ve HakemBelge kayıtlarını oluştur
        for belge in basvuru.belgeler:
            eski_belge_yolu = os.path.join(current_app.config['HAKEM_ADAY_UPLOAD_FOLDER'], belge.belge_yolu)
            yeni_belge_adi = f"hakem_{tc_kimlik_no}_{belge.belge_tipi}.{belge.belge_yolu.rsplit('.', 1)[1]}"
            yeni_belge_yolu = os.path.join(current_app.config['BELGE_UPLOAD_FOLDER'], yeni_belge_adi)

            # Yolları str türüne dönüştür
            eski_belge_yolu = str(eski_belge_yolu)
            yeni_belge_yolu = str(yeni_belge_yolu)

            if os.path.exists(eski_belge_yolu):
                shutil.move(eski_belge_yolu, yeni_belge_yolu)

            yeni_hakem_belge = HakemBelge(hakem_id=yeni_hakem.id, belge_yolu=yeni_belge_adi)
            db.session.add(yeni_hakem_belge)

        db.session.delete(basvuru)
        db.session.commit()
        flash('Hakem başvurusu onaylandı ve kullanıcı oluşturuldu', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Hata: {str(e)}', 'danger')

    return redirect(url_for('hakem_basvuru_listesi'))


@app.route('/spor_dali_ekle', methods=['GET', 'POST'])
@check_permission('Yonetici')
def spor_dali_ekle():
    if request.method == 'POST':
        yeni_spor_dali = SporDali(dal_adi=request.form['spor_dali_adi'])
        db.session.add(yeni_spor_dali)
        db.session.commit()
        return redirect(url_for('spor_dallari_ve_sonuc_turleri_listele'))

    return render_template('spor_dali_ekle.html')


@app.route('/sonuc_turu_ekle', methods=['GET', 'POST'])
@check_permission('Yonetici')
def sonuc_turu_ekle():
    if request.method == 'POST':
        yeni_sonuc_turu = SonucTuru(tur_adi=request.form['sonuc_turu_adi'])
        db.session.add(yeni_sonuc_turu)
        db.session.commit()
        return redirect(url_for('spor_dallari_ve_sonuc_turleri_listele'))

    return render_template('sonuc_turu_ekle.html')


@app.route('/spor_dali_duzenle/<int:id>', methods=['GET', 'POST'])
@check_permission('Yonetici')
def spor_dali_duzenle(id):
    spor_dali = SporDali.query.get_or_404(id)
    if request.method == 'POST':
        spor_dali.dal_adi = request.form['spor_dali_adi']
        db.session.commit()
        return redirect(url_for('spor_dallari_ve_sonuc_turleri_listele'))

    return render_template('spor_dali_duzenle.html', spor_dali=spor_dali)


@app.route('/sonuc_turu_duzenle/<int:id>', methods=['GET', 'POST'])
@check_permission('Yonetici')
def sonuc_turu_duzenle(id):
    sonuc_turu = SonucTuru.query.get_or_404(id)
    if request.method == 'POST':
        sonuc_turu.tur_adi = request.form['sonuc_turu_adi']
        db.session.commit()
        return redirect(url_for('spor_dallari_ve_sonuc_turleri_listele'))

    return render_template('sonuc_turu_duzenle.html', sonuc_turu=sonuc_turu)


@app.route('/spor_dali_sil/<int:id>', methods=['GET', 'POST'])
def spor_dali_sil(id):
    spor_dali = SporDali.query.get_or_404(id)
    db.session.delete(spor_dali)
    db.session.commit()
    return redirect(url_for('spor_dallari_ve_sonuc_turleri_listele'))


@app.route('/sonuc_turu_sil/<int:id>', methods=['GET', 'POST'])
def sonuc_turu_sil(id):
    sonuc_turu = SonucTuru.query.get_or_404(id)
    db.session.delete(sonuc_turu)
    db.session.commit()
    return redirect(url_for('spor_dallari_ve_sonuc_turleri_listele'))


@app.route('/spor_dallari_ve_sonuc_turleri')
@check_permission('Yonetici')
def spor_dallari_ve_sonuc_turleri_listele():
    spor_dallari = SporDali.query.all()
    sonuc_turleri = SonucTuru.query.all()
    return render_template('spordalivesonuclistele.html', spor_dallari=spor_dallari, sonuc_turleri=sonuc_turleri)


@app.route('/musabaka/<int:musabaka_id>/sonuclari_gir', methods=['GET', 'POST'])
@login_required
@check_permission('Yonetici')
def musabaka_sonuclari_gir(musabaka_id):
    musabaka = Musabaka.query.get_or_404(musabaka_id)
    brans = musabaka.brans
    katilimcilar = (
        Katilimci.query
        .join(Sporcu, Katilimci.sporcu_id == Sporcu.id)
        .filter(Katilimci.musabaka_id == musabaka_id)
        .all()
    )

    # Mevcut sonuçları sorgulama ve saklama
    mevcut_sonuclar = {}
    for katilimci in katilimcilar:
        sonuclar = SporDaliSonuc.query.filter_by(musabaka_id=musabaka_id, sporcu_id=katilimci.sporcu.id).all()
        mevcut_sonuclar[katilimci.sporcu.id] = {sonuc.sonucturu_id: sonuc.deger for sonuc in sonuclar}

    if request.method == 'POST':
        # Form verilerini işleme ve kaydetme
        for katilimci in katilimcilar:
            for sonuc_turu in brans.sonuc_turleri:
                deger = request.form.get(f'{sonuc_turu.id}_{katilimci.sporcu.id}')
                spordali_id = 1  # Bu değeri uygun şekilde güncelleyin

                # Veritabanında mevcut sonuçları sorgula
                mevcut_sonuc = SporDaliSonuc.query.filter_by(
                    musabaka_id=musabaka_id,
                    sporcu_id=katilimci.sporcu.id,
                    sonucturu_id=sonuc_turu.id,
                ).first()

                if mevcut_sonuc:
                    # Mevcut sonuç varsa güncelle
                    mevcut_sonuc.spordali_id = spordali_id
                    mevcut_sonuc.deger = deger
                else:
                    # Mevcut sonuç yoksa yeni sonuç oluştur
                    yeni_sonuc = SporDaliSonuc(
                        musabaka_id=musabaka_id,
                        sporcu_id=katilimci.sporcu.id,
                        sonucturu_id=sonuc_turu.id,
                        spordali_id=spordali_id,
                        yas_kategori_id=katilimci.yas_kategori_id,
                        deger=deger
                    )
                    db.session.add(yeni_sonuc)

        # Veritabanı işlemlerini gerçekleştirme
        try:
            db.session.commit()
            flash('Sonuçlar başarıyla kaydedildi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Sonuçları kaydederken bir hata oluştu: {e}', 'danger')

        return redirect(url_for('musabaka_sonuclari_gir', musabaka_id=musabaka_id))

    return render_template('musabaka_sonuclari_gir.html', musabaka=musabaka, katilimcilar=katilimcilar, brans=brans,
                           mevcut_sonuclar=mevcut_sonuclar)


@app.route('/tum_musabakalar')
def tum_musabakalar():
    current_date = date.today()

    # Yıl ve ay seçimini al
    selected_year = request.args.get('year')
    selected_month = request.args.get('month')
    page = request.args.get('page', 1, type=int)
    per_page = 6  # Sayfa başına gösterilecek müsabaka sayısı

    # Geçersiz year ve month değerleri için varsayılan değerler belirleyin
    try:
        selected_year = int(selected_year) if selected_year and selected_year.isdigit() else current_date.year
    except ValueError:
        selected_year = current_date.year

    try:
        selected_month = int(selected_month) if selected_month and selected_month.isdigit() else None
    except ValueError:
        selected_month = None

    # Yıllar listesini veritabanından alın
    year_list = db.session.query(func.extract('year', Musabaka.baslama_tarihi).label('year')).distinct().order_by(
        'year').all()
    year_list = [int(year.year) for year in year_list]  # Yılları listeye dönüştürün

    # Aylar listesini oluştur, yalnızca seçilen yılda müsabakası olan aylar
    month_list = []
    if selected_year != "all":
        month_list = db.session.query(
            func.extract('month', Musabaka.baslama_tarihi).label('month')
        ).filter(
            func.extract('year', Musabaka.baslama_tarihi) == selected_year
        ).group_by(
            func.extract('month', Musabaka.baslama_tarihi)
        ).having(func.count(Musabaka.id) > 0).order_by('month').all()

        # Ayları listeye dönüştürün
        month_list = [int(month.month) for month in month_list]

    # Seçilen yıl için musabaka sorgusunu oluştur
    musabakalar_query = Musabaka.query

    if selected_year != "all":
        musabakalar_query = musabakalar_query.filter(
            func.extract('year', Musabaka.baslama_tarihi) == selected_year)
    if selected_month:
        musabakalar_query = musabakalar_query.filter(
            func.extract('month', Musabaka.baslama_tarihi) == selected_month)
    if selected_month == "all" and selected_year != "all":
        musabakalar_query = musabakalar_query.filter(
            func.extract('year', Musabaka.baslama_tarihi) == selected_year)

    musabakalar_query = musabakalar_query.order_by(Musabaka.baslama_tarihi.desc())

    # Tüm sorguyu çalıştır ve sonuçları al
    musabakalar = musabakalar_query.all()

    # Müsabakalara katılım bilgilerini ekle
    for musabaka in musabakalar:
        kayitli_sporcu_sayisi = Katilimci.query.filter_by(musabaka_id=musabaka.id).filter(
            Katilimci.sporcu_id.isnot(None)).count()
        kadin_sporcu_sayisi = db.session.query(Sporcu.id).join(Katilimci, Sporcu.id == Katilimci.sporcu_id).filter(
            Katilimci.musabaka_id == musabaka.id, Sporcu.cinsiyet == 'Kadın').count()
        erkek_sporcu_sayisi = db.session.query(Sporcu.id).join(Katilimci, Sporcu.id == Katilimci.sporcu_id).filter(
            Katilimci.musabaka_id == musabaka.id, Sporcu.cinsiyet == 'Erkek').count()
        kulup_sayisi = db.session.query(Kulup.id).join(Sporcu, Sporcu.kulup_id == Kulup.id).join(
            Katilimci, Katilimci.sporcu_id == Sporcu.id).filter(
            Katilimci.musabaka_id == musabaka.id).group_by(Kulup.id).count()
        il_temsilcisi_sayisi = db.session.query(Sporcu.il_temsilcisi_id).join(Katilimci,
                                                                              Sporcu.id == Katilimci.sporcu_id).filter(
            Katilimci.musabaka_id == musabaka.id).filter(Sporcu.il_temsilcisi_id.isnot(None)).group_by(
            Sporcu.il_temsilcisi_id).count()

        musabaka.kayitli_sporcu_sayisi = kayitli_sporcu_sayisi
        musabaka.kadin_sporcu_sayisi = kadin_sporcu_sayisi
        musabaka.erkek_sporcu_sayisi = erkek_sporcu_sayisi
        musabaka.kulup_sayisi = kulup_sayisi
        musabaka.il_temsilcisi_sayisi = il_temsilcisi_sayisi

    # Sayfalama
    total_musabaka = len(musabakalar)
    total_pages = ceil(total_musabaka / per_page)
    musabakalar = musabakalar[(page - 1) * per_page: page * per_page]

    # Eğer JSON isteği yapılmışsa, sadece ayları JSON olarak döndür
    if selected_year and request.headers.get('Accept') == 'application/json':
        return jsonify({'months': [{'month': month, 'name': get_month_name(month)} for month in month_list]})

    # Normal HTTP isteği ise şablonu render et
    return render_template('tum_musabakalar.html', musabakalar=musabakalar, page=page, total_pages=total_pages,
                           selected_year=selected_year, selected_month=selected_month, year_list=year_list,
                           month_list=month_list)


def get_month_name(month):
    month_names = {1: 'Ocak', 2: 'Şubat', 3: 'Mart', 4: 'Nisan', 5: 'Mayıs', 6: 'Haziran',
                   7: 'Temmuz', 8: 'Ağustos', 9: 'Eylül', 10: 'Ekim', 11: 'Kasım', 12: 'Aralık'}
    return month_names.get(month, "Unknown")


def ilk_sonucu_bul(sporcu_verileri, musabaka_id):
    for sonuc in sporcu_verileri['sonuclar']:
        if sonuc.sonucturu_id == 15 and sonuc.musabaka_id == musabaka_id:
            return sonuc.deger
    return None


@app.route('/get_match_details')
def get_match_details():
    musabaka_id = request.args.get('id')

    # Müsabakayı veritabanından alın
    musabaka = db.session.get(Musabaka, musabaka_id)

    if musabaka is None:
        return jsonify({'error': 'Müsabaka bulunamadı'}), 404

    # Müsabakaya katılım bilgilerini ekle
    kayitli_sporcu_sayisi = Katilimci.query.filter_by(musabaka_id=musabaka.id).filter(Katilimci.sporcu_id.isnot(None)).count()
    kadin_sporcu_sayisi = db.session.query(Sporcu.id).join(Katilimci, Sporcu.id == Katilimci.sporcu_id).filter(
        Katilimci.musabaka_id == musabaka.id, Sporcu.cinsiyet == 'Kadın').count()
    erkek_sporcu_sayisi = db.session.query(Sporcu.id).join(Katilimci, Sporcu.id == Katilimci.sporcu_id).filter(
        Katilimci.musabaka_id == musabaka.id, Sporcu.cinsiyet == 'Erkek').count()
    kulup_sayisi = db.session.query(Kulup.id).join(Sporcu, Sporcu.kulup_id == Kulup.id).join(
        Katilimci, Katilimci.sporcu_id == Sporcu.id).filter(
        Katilimci.musabaka_id == musabaka.id).group_by(Kulup.id).count()

    # Müsabaka bilgilerini JSON formatında döndür
    return jsonify({
        'musabaka_adi': musabaka.musabaka_adi,
        'baslama_tarihi': musabaka.baslama_tarihi.strftime('%d/%m/%Y'),
        'bitis_tarihi': musabaka.bitis_tarihi.strftime('%d/%m/%Y'),
        'il': musabaka.il,
        'kadin_sporcu_sayisi': kadin_sporcu_sayisi,
        'erkek_sporcu_sayisi': erkek_sporcu_sayisi,
        'kayitli_sporcu_sayisi': kayitli_sporcu_sayisi,
        'kulup_sayisi': kulup_sayisi
    })


@app.route('/check_start_list_status/<int:musabaka_id>')
def check_start_list_status(musabaka_id):
    musabaka = db.session.get(Musabaka, musabaka_id)
    if musabaka and musabaka.start_listesi_aktif:
        return jsonify({'status': 'ready'})
    else:
        return jsonify({'status': 'not_ready'})


@app.route('/check_results_status/<int:musabaka_id>')
def check_results_status(musabaka_id):
    musabaka = db.session.get(Musabaka, musabaka_id)
    if musabaka:
        # Sonuçların mevcut olup olmadığını kontrol et
        sonuclar_var = db.session.query(SporDaliSonuc).filter_by(musabaka_id=musabaka_id).count() > 0
        if sonuclar_var:
            return jsonify({'status': 'ready'})
        else:
            return jsonify({'status': 'not_ready'})
    else:
        return jsonify({'status': 'not_ready'})


@app.route('/musabaka/<int:musabaka_id>/sonuclar')
def musabaka_sonuclari(musabaka_id):
    # Müsabakayı veritabanından al veya 404 hatası döndür
    musabaka = Musabaka.query.get_or_404(musabaka_id)

    # Eğer sonuçlar henüz yayınlanmadıysa, kullanıcıyı bilgilendir ve yönlendir
    if not musabaka.start_listesi_aktif:
        flash('Bu müsabaka için sonuç listesi henüz yayınlanmadı.', 'error')
        return redirect(url_for('tum_musabakalar'))

    # Müsabakaya katılan sporcuların sonuçlarını al
    sonuc_raw = db.session.query(Katilimci, SporDaliSonuc) \
        .join(SporDaliSonuc, Katilimci.sporcu_id == SporDaliSonuc.sporcu_id) \
        .filter(SporDaliSonuc.musabaka_id == musabaka_id) \
        .all()

    sonuclar = {}
    for katilimci, spor_dali_sonuc in sonuc_raw:
        sporcu_id = katilimci.sporcu_id
        yas_kategori = db.session.get(YasKategorisi, spor_dali_sonuc.yas_kategori_id)
        if sporcu_id not in sonuclar:
            sonuclar[sporcu_id] = {
                'sporcu': katilimci.sporcu,
                'yas_kategori': yas_kategori,
                'sonuclar': []
            }

        # Aynı sonucun tekrar eklenmemesi için kontrol
        if not any(s.id == spor_dali_sonuc.id for s in sonuclar[sporcu_id]['sonuclar']):
            sonuclar[sporcu_id]['sonuclar'].append(spor_dali_sonuc)

    # Yaş kategorisi ve cinsiyet bazında sonuçları filtreleme ve sıralama
    yas_kategori_siralama = ["U9", "U11", "U13", "U15", "U17", "U19", "GENÇLER", "BÜYÜKLER", "MASTER +30", "MASTER +40", "MASTER +50", "MASTER +60", "MASTER +70", "MASTER +80"]
    cinsiyet_siralama = ["Kadın", "Erkek"]

    def get_sira_degeri(sporcu_verisi):
        sira_degeri = ilk_sonucu_bul(sporcu_verisi, musabaka_id)
        if sira_degeri is not None:
            try:
                return int(sira_degeri)
            except ValueError:
                return float('inf')
        return float('inf')

    sonuclar_filtered_sirali = {}
    for yas_kategori, cinsiyet in itertools.product(yas_kategori_siralama, cinsiyet_siralama):
        filtered = [
            sporcu_verisi for sporcu_verisi in sonuclar.values()
            if (
                    sporcu_verisi['sporcu'].cinsiyet == cinsiyet and
                    sporcu_verisi.get('yas_kategori') and
                    sporcu_verisi['yas_kategori'].yas_kategori_adi == yas_kategori
            )
        ]

        for sporcu_verisi in filtered:
            sporcu_verisi['sonuclar'] = [
                s for s in sporcu_verisi['sonuclar'] if s.musabaka_id == musabaka_id
            ]
            sporcu_verisi['ilk_sonuc_15'] = ilk_sonucu_bul(sporcu_verisi, musabaka_id)

        filtered_sorted = sorted(filtered, key=get_sira_degeri)
        if filtered_sorted:
            sonuclar_filtered_sirali[(yas_kategori, cinsiyet)] = filtered_sorted

    return render_template('musabaka_sonuclari.html', musabaka=musabaka, sonuclar_filtered=sonuclar_filtered_sirali)


@app.route('/indir_excel/<int:musabaka_id>')
def indir_excel(musabaka_id):
    # Sporcular için en son sonuçları getiren sorgu
    son_sonuclar = db.session.query(
        Katilimci.sporcu_id,
        func.max(SporDaliSonuc.id).label('son_sonuc_id')
    ).join(SporDaliSonuc, Katilimci.sporcu_id == SporDaliSonuc.sporcu_id)\
     .filter(SporDaliSonuc.musabaka_id == musabaka_id)\
     .group_by(Katilimci.sporcu_id)\
     .subquery()

    # En son sonuçları ve ilgili katılımcı bilgilerini getiren sorgu
    final_results = db.session.query(Katilimci, SporDaliSonuc, Sporcu, YasKategorisi, Kulup)\
        .join(son_sonuclar, Katilimci.sporcu_id == son_sonuclar.c.sporcu_id)\
        .join(SporDaliSonuc, SporDaliSonuc.id == son_sonuclar.c.son_sonuc_id)\
        .join(Sporcu, Sporcu.id == Katilimci.sporcu_id)\
        .outerjoin(YasKategorisi, YasKategorisi.id == Sporcu.yas_kategori_id)\
        .outerjoin(Kulup, Kulup.id == Sporcu.kulup_id)\
        .all()

    # Sorgu sonuçlarını düzgün bir formata dönüştürme
    sonuclar_listesi = []
    for index, (katilimci, spordali_sonuc, sporcu, yas_kategori, kulup) in enumerate(final_results):
        yas_kategori_adi = katilimci.yas_kategori.yas_kategori_adi if katilimci.yas_kategori else 'Bilgi Yok'
        kulup_adi = kulup.kulup_adi if kulup else 'Ferdi'

        sonuclar_listesi.append([
            index + 1,  # Sıra
            sporcu.ad_soyad,  # Sporcu Adı
            sporcu.dogum_tarihi.year if sporcu.dogum_tarihi else 'Bilgi Yok',  # Doğum Yılı
            sporcu.cinsiyet,  # Cinsiyet
            yas_kategori_adi,  # Yaş Kategorisi
            kulup_adi,  # Kulüp
            spordali_sonuc.deger  # Sonuç
        ])

    # DataFrame oluşturma
    df = pd.DataFrame(
        sonuclar_listesi,
        columns=['Sıra', 'Sporcu Adı', 'Doğum Yılı', 'Cinsiyet', 'Yaş Kategorisi', 'Kulüp', 'Sonuç']
    )

    # Excel dosyası yolu
    excel_path = f"musabaka_{musabaka_id}_sonuclari.xlsx"

    # ExcelWriter ile Excel dosyasını aç
    with ExcelWriter(excel_path) as writer:
        # Yaş kategorisi ve cinsiyete göre gruplandır
        for (yas_kategori, cinsiyet), group in df.groupby(['Yaş Kategorisi', 'Cinsiyet']):
            # Her gruptaki sıra numarasını 1'den başlat
            group['Sıra'] = range(1, len(group) + 1)

            # Sayfa adını oluştur
            sheet_name = f"{yas_kategori} {cinsiyet}"
            # Grubu Excel sayfasına yaz
            group.to_excel(writer, sheet_name=sheet_name, index=False)

    # Dosyayı indirme olarak sun
    return send_file(excel_path, as_attachment=True)


@app.route('/hakkinda')
def hakkinda():
    # 'hakkinda.html' şablonunu kullanarak Hakkında sayfasını render et
    return render_template('hakkinda.html', title='Sistem Hakkında')


@app.route('/sifre-sifirlama-talebi', methods=['GET'])
def sifre_sifirlama_talebi():
    return render_template('sifre_sifirlama_talebi.html')


@app.route('/sifre-sifirlama-talebi-gonder', methods=['POST'])
def sifre_sifirlama_talebi_gonder():
    telefon_numarasi = request.form.get('telefon')

    # Telefon numarasının sistemde kayıtlı olup olmadığını kontrol et
    kullanici = None
    for model in [Yonetici, Hakem, Antrenor, Kulup]:
        kullanici = model.query.filter_by(telefon=telefon_numarasi).first()
        if kullanici:
            break

    if kullanici:
        token = secrets.token_urlsafe()
        # Kullanıcıya ait tokeni ve oluşturulma zamanını kaydet
        yeni_token = SifreSifirlamaToken(token=token, kullanici_id=kullanici.kullanici_id, olusturulma_zamani=datetime.now(timezone.utc))
        db.session.add(yeni_token)
        db.session.commit()

        # Telefon numarasına ait kullanıcı için şifre sıfırlama bağlantısını oluştur ve gönder
        sifre_sifirlama_baglantisi = f"http://78.187.90.250:8000/sifre-sifirlama/{token}"
        sms_gonder(telefon_numarasi, f"Şifre sıfırlama bağlantınız: {sifre_sifirlama_baglantisi}")
        flash('Şifre sıfırlama bağlantısı telefon numaranıza gönderildi.', 'success')
    else:
        flash('Bu telefon numarası ile kayıtlı bir kullanıcı bulunamadı.', 'error')

    return redirect(url_for('sifre_sifirlama_talebi'))


@app.route('/sifre-sifirlama/<token>')
def sifre_sifirlama_formu(token):
    token_obj = SifreSifirlamaToken.query.filter_by(token=token).first()
    if not token_obj or not token_obj.token_gecerli_mi():
        flash('Geçersiz veya süresi dolmuş token.', 'error')
        return redirect(url_for('sifre_sifirlama_talebi'))

    # Token ile ilişkilendirilmiş bir kullanıcı olup olmadığını kontrol edin
    if not token_obj.kullanici_id:
        flash('Bu token ile ilişkilendirilmiş bir kullanıcı bulunamadı.', 'error')
        return redirect(url_for('sifre_sifirlama_talebi'))

    # Token daha önce kullanıldı mı kontrol et
    if token_obj.kullanildi_mi:
        flash('Geçersiz veya süresi dolmuş token.', 'error')
        return redirect(url_for('sifre_sifirlama_talebi'))

    kullanici = token_obj.kullanici

    # Token kullanıldı olarak işaretle
    token_obj.kullanildi_mi = True
    db.session.commit()

    return render_template('sifre_sifirlama.html', token=token, kullanici_adi=kullanici.kullanici_adi)


@app.route('/sifre-sifirlama', methods=['POST'])
def sifre_sifirlama():
    token = request.form.get('token')
    yeni_sifre = request.form.get('yeni_sifre')
    sifre_tekrar = request.form.get('sifre_tekrar')

    # Girilen şifrelerin uyuşup uyuşmadığını kontrol et
    if yeni_sifre != sifre_tekrar:
        flash('Girilen şifreler uyuşmuyor.', 'error')
        return redirect(url_for('sifre_sifirlama_formu', token=token))

    # Token objesini ve token'in geçerliliğini kontrol et
    token_obj = SifreSifirlamaToken.query.filter_by(token=token).first()
    if token_obj and token_obj.token_gecerli_mi():
        kullanici = token_obj.kullanici
        # Yeni şifreyi hash'leyerek güncelle
        hashed_sifre = generate_password_hash(yeni_sifre)
        kullanici.sifre = hashed_sifre
        db.session.commit()

        # Başarı mesajını kullanıcının adıyla birlikte göster
        flash(f"Şifreniz başarıyla güncellendi, {kullanici.kullanici_adi}!", 'success')
        return redirect(url_for('login'))
    else:
        # Token geçersizse veya süresi dolmuşsa hata mesajı göster
        flash('Geçersiz veya süresi dolmuş token.', 'error')
        return redirect(url_for('sifre_sifirlama_formu', token=token))


def sms_gonder(telefon_numarasi, mesaj):
    api_url = 'https://api.netgsm.com.tr/sms/send/get/'
    kullanici_adi = '08503464657'
    sifre = '71951280.Fa'
    header = 'TMPF'

    parametreler = {
        'usercode': kullanici_adi,
        'password': sifre,
        'gsmno': telefon_numarasi,
        'message': mesaj,
        'msgheader': header
    }

    response = requests.get(api_url, params=parametreler)
    if response.status_code == 200:
        print("SMS başarıyla gönderildi.")
        return True  # SMS başarılı bir şekilde gönderildiğini belirt
    else:
        print("SMS gönderimi sırasında bir hata oluştu.")
        return False  # SMS gönderimi sırasında hata oluştuğunu belirt


# Uygulamayı çalıştır
if __name__ == '__main__':
    with app.app_context():
        # Veritabanı tablolarını oluştur
        db.create_all()
    app.run(host='0.0.0.0', port=8000, debug=True)
