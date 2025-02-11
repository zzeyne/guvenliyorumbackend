from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from detoxify import Detoxify
from googletrans import Translator
from contextlib import asynccontextmanager


print("🔄 Detoxify modeli yükleniyor...")
model = Detoxify('original')
print("✅ Detoxify modeli başarıyla yüklendi.")

# Çevirici oluştur
translator = Translator()


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("✅ Backend uygulaması başlatılıyor...")
    yield  # Uygulama başlatılırken yapılacak işlemler burada biter
    print("🛑 Backend uygulaması kapatılıyor.")


app = FastAPI(lifespan=lifespan)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class InputText(BaseModel):
    text: str


@app.get("/")
def root():
    print("🌐 Ana sayfa endpoint çağrıldı.")
    return {"message": "Detoxify API'ye hoş geldiniz!"}


@app.post("/analyze")
def analyze_text(input_text: InputText):
    print(f"📨 Gelen metin: {input_text.text}")

    if not input_text.text.strip():
        print("⚠️ Boş metin gönderildi.")
        return {"error": "Lütfen analiz edilecek bir metin giriniz."}

    try:
        
        translated_text = translator.translate(input_text.text, src='tr', dest='en').text
        print(f"📤 Çevrilen metin (İngilizce): {translated_text}")
        
        
        results = model.predict(translated_text)
        
        results = {key: float(value) for key, value in results.items()} if isinstance(results, dict) else {}
        print(f"🧪 Analiz sonuçları: {results}")
    except Exception as e:
        print(f"❌ Analiz sırasında bir hata oluştu: {str(e)}")
        return {"error": f"Analiz sırasında bir hata oluştu: {str(e)}"}

    # Türk Ceza Kanunu (TCK) eşleştirmesi
    tck_mapping = {
        "threat": {"tck": "TCK 106", "açıklama": "Tehdit"},
        "insult": {"tck": "TCK 125", "açıklama": "Hakaret"},
        
        "toxicity": {"tck": "TCK 216", "açıklama": "Halkı kin ve düşmanlığa tahrik"},
        "identity_attack": {"tck": "TCK 216", "açıklama": "Kimlik saldırısı"},
    }

    # Skorların maddelerle eşleştirildiği kısım
    response = []
    for key, value in results.items():
        if key in tck_mapping and value > 0.2:  
            response.append({
                "tur": key,
                "tck": tck_mapping[key]["tck"],
                "aciklama": tck_mapping[key]["açıklama"],
                "skor": round(value, 2)
            })

    # Çevrilen sonucu Türkçeye geri çevir
    final_response = {
        "analyze_results": response
    }
    print(f"🔍 Döndürülen sonuç: {final_response}")
    return final_response
