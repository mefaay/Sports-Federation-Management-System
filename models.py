from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
from enum import Enum, unique
from sqlalchemy import func, Column, Integer, String, DateTime
from datetime import datetime, timedelta, timezone
from flask import current_app
import pytz
import os

# SQLAlchemy instance'ını oluşturuyoruz
db = SQLAlchemy()


def convert_utc_to_local(utc_dt):
    local_tz = pytz.timezone("Europe/Istanbul")
    local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
    return local_tz.normalize(local_dt)


class Duyuru(db.Model):
    __tablename__ = 'duyurular'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    baslik = db.Column(db.String(255), nullable=False)
    icerik = db.Column(db.Text, nullable=False)
    yayinlanma_tarihi = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    yazar_id = db.Column(db.Integer, db.ForeignKey('kullanicilar.id'))
    yazar = db.relationship('Kullanici', backref='duyurular')


# Musabaka ve YasKategorisi arasında çoktan çoğa ilişki tablosu
musabaka_yas_kategori = db.Table(
    'musabaka_yas_kategori',
    db.Column('musabaka_id', db.Integer, db.ForeignKey('musabakalar.id'), primary_key=True),
    db.Column('yas_kategori_id', db.Integer, db.ForeignKey('yaskategorileri.id'), primary_key=True)
)


@unique
class Rol(Enum):
    Yonetici = 'Yonetici'
    Kulup = 'Kulup'
    Antrenor = 'Antrenor'
    IlTemsilcisi = 'IlTemsilcisi'
    Hakem = 'Hakem'


class BelgeTipi(Enum):
    CEZASI_YOKTUR = "Cezası Yoktur"
    OGRENIM_BELGESI = "Öğrenim Belgesi"
    NUFUS_CUZDANI = "Nüfus Cüzdanı"
    ADLI_SICIL = "Adli Sicil"
    SAGLIK_RAPORU = "Sağlık Raporu"
    DEKONT = "Dekont"


class Kullanici(db.Model):
    __tablename__ = 'kullanicilar'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    kullanici_adi = db.Column(db.String(255), unique=True, nullable=False)
    sifre = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.Enum(Rol), nullable=False)
    aktif = db.Column(db.Boolean, default=True)


class Yonetici(db.Model):
    __tablename__ = 'yoneticiler'
    id = db.Column(db.Integer, primary_key=True)
    foto = db.Column(db.String(255))
    ad_soyad = db.Column(db.String(255), nullable=False)
    gorevi = db.Column(db.String(255))
    telefon = db.Column(db.String(50))
    eposta = db.Column(db.String(255))
    adres = db.Column(db.Text)
    il = db.Column(db.String(255))
    tc_kimlik_no = db.Column(db.String(11), unique=True, nullable=False)
    kullanici_id = db.Column(db.Integer, db.ForeignKey('kullanicilar.id'), nullable=False)
    kullanici = db.relationship('Kullanici', backref='yonetici')


class SporDali(db.Model):
    __tablename__ = 'spordallari'
    id = db.Column(db.Integer, primary_key=True)
    dal_adi = db.Column(db.String(255), unique=True)


class SonucTuru(db.Model):
    __tablename__ = 'sonucturleri'
    id = db.Column(db.Integer, primary_key=True)
    tur_adi = db.Column(db.String(255), unique=True)


class BransSporDali(db.Model):
    __tablename__ = 'bransspordali'
    id = db.Column(db.Integer, primary_key=True)
    brans_id = db.Column(db.Integer, db.ForeignKey('branslar.id'))
    spordali_id = db.Column(db.Integer, db.ForeignKey('spordallari.id'))


class SporDaliSonuc(db.Model):
    __tablename__ = 'spordalisonuclari'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    musabaka_id = db.Column(db.Integer, db.ForeignKey('musabakalar.id'), nullable=False)
    sporcu_id = db.Column(db.Integer, db.ForeignKey('sporcular.id'), nullable=False)
    spordali_id = db.Column(db.Integer, db.ForeignKey('spordallari.id'), nullable=False)
    sonucturu_id = db.Column(db.Integer, db.ForeignKey('sonucturleri.id'), nullable=False)
    yas_kategori_id = db.Column(db.Integer, db.ForeignKey('yaskategorileri.id'), nullable=False)
    deger = db.Column(db.String)

    musabaka = db.relationship('Musabaka', backref='spordalisonuclari')
    sporcu = db.relationship('Sporcu', backref='spordalisonuclari')
    spordali = db.relationship('SporDali', backref='spordalisonuclari')
    sonucturu = db.relationship('SonucTuru', backref='spordalisonuclari')
    yas_kategori = db.relationship('YasKategorisi', backref='spordalisonuclari')


class BransSonucTuru(db.Model):
    __tablename__ = 'branssonucturu'
    id = db.Column(db.Integer, primary_key=True)
    brans_id = db.Column(db.Integer, db.ForeignKey('branslar.id'))
    sonucturu_id = db.Column(db.Integer, db.ForeignKey('sonucturleri.id'))


class Brans(db.Model):
    __tablename__ = 'branslar'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    brans_adi = db.Column(db.String(255), unique=True, nullable=False)
    spor_dallari = db.relationship('SporDali', secondary='bransspordali')
    sonuc_turleri = db.relationship('SonucTuru', secondary='branssonucturu')


class YasKategorisi(db.Model):
    __tablename__ = 'yaskategorileri'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    yas_kategori_adi = db.Column(db.String(255), unique=True, nullable=False)


class Kulup(db.Model):
    __tablename__ = 'kulupler'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    logo_url = db.Column(db.String(255))
    kulup_adi = db.Column(db.String(255), nullable=False)
    kutuk_no = db.Column(db.String(50))
    baskan_adi = db.Column(db.String(255))
    telefon = db.Column(db.String(50))
    eposta = db.Column(db.String(255))
    iban = db.Column(db.String(50))
    adres = db.Column(db.Text)
    il = db.Column(db.String(255))
    kullanici_id = db.Column(db.Integer, db.ForeignKey('kullanicilar.id'))
    kullanici = db.relationship('Kullanici', backref='kulupler')


class Sporcu(db.Model):
    __tablename__ = 'sporcular'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    foto = db.Column(db.String(255))
    ad_soyad = db.Column(db.String(255), nullable=False)
    tc_no = db.Column(db.String(11), unique=True)
    dogum_tarihi = db.Column(db.Date)
    lisans_no = db.Column(db.String(50), unique=True)
    cinsiyet = db.Column(db.String(50), nullable=False)
    adres = db.Column(db.Text)
    il = db.Column(db.String(255))
    telefon = db.Column(db.String(50))
    kulup_id = db.Column(db.Integer, db.ForeignKey('kulupler.id'), nullable=True)
    il_temsilcisi_id = db.Column(db.Integer, db.ForeignKey('iltemsilcileri.id'), nullable=True)

    kulup = db.relationship('Kulup', backref='sporcular', foreign_keys=[kulup_id])
    il_temsilcisi = db.relationship('IlTemsilcisi', backref='ferdi_sporcular', foreign_keys=[il_temsilcisi_id])

    # Yeni eklenen alanlar
    aktif = db.Column(db.Boolean, default=True)
    transfer_edildi = db.Column(db.Boolean, default=False)
    transfer_tarihi = db.Column(db.DateTime, nullable=True)
    transfer_kulubu_id = db.Column(db.Integer, db.ForeignKey('kulupler.id'), nullable=True)
    transfer_il_temsilcisi_id = db.Column(db.Integer, db.ForeignKey('iltemsilcileri.id'), nullable=True)
    eski_sporcu_id = db.Column(db.Integer, db.ForeignKey('sporcular.id'), nullable=True)

    transfer_kulubu = db.relationship('Kulup', foreign_keys=[transfer_kulubu_id])
    transfer_il_temsilcisi = db.relationship('IlTemsilcisi', foreign_keys=[transfer_il_temsilcisi_id])
    eski_sporcu = db.relationship('Sporcu', remote_side=[id], backref='yeni_sporcu')

    @validates('kulup_id', 'il_temsilcisi_id')
    def validate_sporcu_type(self, key, value):
        if key == 'kulup_id' and value is not None:
            self.il_temsilcisi_id = None
        elif key == 'il_temsilcisi_id' and value is not None:
            self.kulup_id = None
        return value

    def transfer_et(self, yeni_kulup_id=None, yeni_il_temsilcisi_id=None):
        # Eski sporcuyu pasif yap ve transfer bilgilerini ekle
        self.aktif = False
        self.transfer_edildi = True
        self.transfer_tarihi = datetime.now()

        # Eski sporcunun kulüp ve il temsilcisi bilgilerini kaydet
        self.transfer_kulubu_id = self.kulup_id
        self.transfer_il_temsilcisi_id = self.il_temsilcisi_id

        # T.C. Kimlik numarası ve lisans numarası yeni sporcuya aktarılacak
        eski_tc_no = self.tc_no
        eski_lisans_no = self.lisans_no

        # T.C. Kimlik numarası ve lisans numarasını eski sporcudan temizleyelim (isteğe bağlı)
        self.tc_no = None
        self.lisans_no = None

        db.session.commit()

        # Yeni sporcu oluşturma
        yeni_sporcu = Sporcu(
            ad_soyad=self.ad_soyad,
            tc_no=eski_tc_no,  # Eski kayıttaki TC kimlik numarasını yeni kayda aktar
            dogum_tarihi=self.dogum_tarihi,
            lisans_no=eski_lisans_no,  # Eski kayıttaki lisans numarasını yeni kayda aktar
            cinsiyet=self.cinsiyet,
            adres=self.adres,
            il=self.il,
            telefon=self.telefon,
            kulup_id=yeni_kulup_id,
            il_temsilcisi_id=yeni_il_temsilcisi_id,
            foto=self.foto,
            transfer_tarihi=self.transfer_tarihi,
            eski_sporcu_id=self.id,  # Yeni sporcunun eski sporcu ile bağlantısı
            transfer_kulubu_id=yeni_kulup_id,  # Yeni kulüp ID'sini kaydediyoruz
            transfer_il_temsilcisi_id=yeni_il_temsilcisi_id  # Yeni il temsilcisi ID'sini kaydediyoruz
        )

        db.session.add(yeni_sporcu)
        db.session.commit()
        return yeni_sporcu


class Antrenor(db.Model):
    __tablename__ = 'antrenorler'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    foto = db.Column(db.String(255))
    tc_kimlik_no = db.Column(db.String(11), unique=True, nullable=False)
    ad_soyad = db.Column(db.String(255), nullable=False)
    telefon = db.Column(db.String(50))
    eposta = db.Column(db.String(255))
    adres = db.Column(db.Text)
    kullanici_id = db.Column(db.Integer, db.ForeignKey('kullanicilar.id'))
    kulup_id = db.Column(db.Integer, db.ForeignKey('kulupler.id'))

    kulup = db.relationship('Kulup', backref=db.backref('antrenorler', lazy=True))


class IlTemsilcisi(db.Model):
    __tablename__ = 'iltemsilcileri'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    foto = db.Column(db.String(255))
    tc_kimlik_no = db.Column(db.String(11), unique=True, nullable=False)
    il = db.Column(db.String(255), nullable=False)
    ad_soyad = db.Column(db.String(255), nullable=False)
    telefon = db.Column(db.String(50))
    eposta = db.Column(db.String(255))
    adres = db.Column(db.Text)
    kullanici_id = db.Column(db.Integer, db.ForeignKey('kullanicilar.id'))
    kullanici = db.relationship('Kullanici', backref='iltemsilcileri')


# İlişki tablosu hakemler ve müsabakalar arasında çoktan çoğa ilişki kurar
musabaka_hakem = db.Table(
    'musabaka_hakem',
    db.Column('musabaka_id', db.Integer, db.ForeignKey('musabakalar.id'), primary_key=True),
    db.Column('hakem_id', db.Integer, db.ForeignKey('hakemler.id'), primary_key=True),
    db.Column('gorevlendirme_tarihi', db.Date, default=func.current_date())
)


class Hakem(db.Model):
    __tablename__ = 'hakemler'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    foto = db.Column(db.String(255))
    ad_soyad = db.Column(db.String(255), nullable=False)
    tc_kimlik_no = db.Column(db.String(11), unique=True, nullable=False)
    kutuk_no = db.Column(db.String(50))
    derece = db.Column(db.String(50), nullable=False)
    telefon = db.Column(db.String(50))
    dogum_tarihi = db.Column(db.Date)
    eposta = db.Column(db.String(255))
    adres = db.Column(db.Text)
    izin_adresi = db.Column(db.Text)
    il = db.Column(db.String(255))
    iban = db.Column(db.String(50))
    kullanici_id = db.Column(db.Integer, db.ForeignKey('kullanicilar.id'))
    mhk_uyesi_mi = db.Column(db.Boolean, default=False)

    # İlişkilendirme
    kullanici = db.relationship('Kullanici', backref='hakem', lazy=True)

    belgeler = db.relationship('HakemBelge', back_populates='hakem', lazy=True)
    musabakalar = db.relationship('Musabaka', secondary=musabaka_hakem, back_populates='hakemler')


class HakemBelge(db.Model):
    __tablename__ = 'hakem_belge'
    id = db.Column(db.Integer, primary_key=True)
    hakem_id = db.Column(db.Integer, db.ForeignKey('hakemler.id'))
    belge_tipi = db.Column(db.String(50))
    belge_yolu = db.Column(db.String(255))

    hakem = db.relationship('Hakem', back_populates='belgeler')


class HakemBasvuru(db.Model):
    __tablename__ = 'hakem_basvurulari'
    id = db.Column(db.Integer, primary_key=True)
    derece = db.Column(db.String(50), nullable=False, default='Aday Hakem')
    ad_soyad = db.Column(db.String(255), nullable=False)
    tc_kimlik_no = db.Column(db.String(11), unique=True, nullable=False)
    dogum_tarihi = db.Column(db.Date, nullable=False)
    telefon = db.Column(db.String(50), nullable=False)
    eposta = db.Column(db.String(255), nullable=False)
    iban = db.Column(db.String(50), nullable=False)
    adres = db.Column(db.Text, nullable=False)
    il = db.Column(db.String(50), nullable=False)
    kutuk_no = db.Column(db.String(50), nullable=True)
    izin_adresi = db.Column(db.Text)
    foto = db.Column(db.String(255))

    belgeler = db.relationship('HakemBelgeBasvuru', backref='hakem_basvuru', lazy=True)

    onay_durumu = db.Column(db.Boolean, default=False)

    def delete_with_belgeler(self):
        try:
            belgeler = HakemBelgeBasvuru.query.filter_by(basvuru_id=self.id).all()
            for belge in belgeler:
                dosya_yolu = os.path.join(current_app.config['HAKEM_ADAY_UPLOAD_FOLDER'], belge.belge_yolu)
                if os.path.exists(dosya_yolu):
                    os.remove(dosya_yolu)
            for belge in belgeler:
                db.session.delete(belge)
            if self.foto:
                foto_yolu = os.path.join(current_app.config['HAKEM_ADAY_UPLOAD_FOLDER'], self.foto)
                if os.path.exists(foto_yolu):
                    os.remove(foto_yolu)
            db.session.delete(self)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e


class HakemBelgeBasvuru(db.Model):
    __tablename__ = 'hakem_belge_basvurulari'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    basvuru_id = db.Column(db.Integer, db.ForeignKey('hakem_basvurulari.id'))
    belge_tipi = db.Column(db.String(50))
    belge_yolu = db.Column(db.String(255))


class GorevlendirmeDurumu(Enum):
    BEKLEMEDE = 'Beklemede'
    ONAYLANDI = 'Onaylandı'
    REDDEDILDI = 'Reddedildi'
    GOREVDEN_KALDIRILDI = 'Görevden Kaldırıldı'  # Yeni durum değeri


class HakemGorevlendirmeTalebi(db.Model):
    __tablename__ = 'hakem_gorevlendirme_talepleri'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    hakem_id = db.Column(db.Integer, db.ForeignKey('hakemler.id'), nullable=False)
    musabaka_id = db.Column(db.Integer, db.ForeignKey('musabakalar.id'), nullable=False)
    talep_tarihi = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    durum = db.Column(db.Enum(GorevlendirmeDurumu), default=GorevlendirmeDurumu.BEKLEMEDE)
    red_sebebi = db.Column(db.String(255), nullable=True)

    hakem = db.relationship('Hakem', backref='gorevlendirme_talepleri')
    musabaka = db.relationship('Musabaka', backref='hakem_talepleri')


class Musabaka(db.Model):
    __tablename__ = 'musabakalar'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    musabaka_adi = db.Column(db.String(255), nullable=False)
    baslama_tarihi = db.Column(db.Date)
    bitis_tarihi = db.Column(db.Date)
    il = db.Column(db.String(255))
    katilimci_ekleme_baslangic_tarihi = db.Column(db.Date)
    katilimci_ekleme_bitis_tarihi = db.Column(db.Date)
    start_listesi_aktif = db.Column(db.Boolean, default=False)
    brans_id = db.Column(db.Integer, db.ForeignKey('branslar.id'))
    brans = db.relationship('Brans', backref='musabakalar')
    yas_kategorileri = db.relationship(
        'YasKategorisi',
        secondary=musabaka_yas_kategori,
        lazy='subquery',
        backref=db.backref('musabakalar', lazy=True)
    )
    hakemler = db.relationship(
        'Hakem',
        secondary=musabaka_hakem,
        back_populates='musabakalar'
    )


class Katilimci(db.Model):
    __tablename__ = 'katilimcilar'
    id = db.Column(db.Integer, primary_key=True)
    sporcu_id = db.Column(db.Integer, db.ForeignKey('sporcular.id'), nullable=True)
    antrenor_id = db.Column(db.Integer, db.ForeignKey('antrenorler.id'), nullable=True)
    musabaka_id = db.Column(db.Integer, db.ForeignKey('musabakalar.id'), nullable=False)
    yas_kategori_id = db.Column(db.Integer, db.ForeignKey('yaskategorileri.id'), nullable=True)
    derece = db.Column(db.String(255), nullable=True)  # Derece alanını ekliyoruz

    sporcu = db.relationship('Sporcu', backref=db.backref('katilimlar', lazy=True))
    antrenor = db.relationship('Antrenor', backref='katilimlar', lazy=True)
    musabaka = db.relationship('Musabaka', backref=db.backref('katilimlar', lazy=True))
    yas_kategori = db.relationship('YasKategorisi', backref=db.backref('katilimlar', lazy=True))


class SifreSifirlamaToken(db.Model):
    __tablename__ = 'sifre_sifirlama_tokenlari'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    kullanici_id = db.Column(db.Integer, db.ForeignKey('kullanicilar.id'), nullable=False)
    kullanici = db.relationship('Kullanici', backref=db.backref('sifre_sifirlama_tokenlari', lazy=True))
    olusturulma_zamani = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    kullanildi_mi = db.Column(db.Boolean, default=False)

    def token_gecerli_mi(self):
        now_utc_aware = datetime.now(timezone.utc)
        olusturulma_zamani_utc_aware = (
            self.olusturulma_zamani
            if self.olusturulma_zamani.tzinfo is not None
            else self.olusturulma_zamani.replace(tzinfo=timezone.utc)
        )
        return (now_utc_aware - olusturulma_zamani_utc_aware) < timedelta(hours=1)


class OnlineKullanici(db.Model):
    __tablename__ = 'online_kullanicilar'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    kullanici_id = db.Column(db.Integer, db.ForeignKey('kullanicilar.id'), nullable=False)
    son_aktif_zaman = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    son_url = db.Column(db.String(255), nullable=True)

    kullanici = db.relationship('Kullanici', backref='online_bilgileri')


class OturumAcmaYetkisiOlmayan(db.Model):
    id = Column(Integer, primary_key=True)
    ip_adresi = Column(String(45))
    url = Column(String(255))
    zaman = Column(DateTime, default=datetime.now(timezone.utc))


class KullaniciGecmis(db.Model):
    __tablename__ = 'kullanici_gecmis'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    kullanici_id = db.Column(db.Integer, db.ForeignKey('kullanicilar.id'), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    zaman = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    ip_adresi = db.Column(db.String(45), nullable=True)

    kullanici = db.relationship('Kullanici', backref='gecmis')
