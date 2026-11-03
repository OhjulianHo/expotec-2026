
/*:
 * @target MZ
 * @plugindesc Guarda y carga partidas de RPG Maker MZ en MongoDB mediante Amaeno.
 * @author Amaeno
 *
 * @help
 * Requiere que el jugador haya iniciado sesión en Amaeno.
 * Las partidas se guardan en el servidor según el usuario del token JWT.
 */

(() => {
    "use strict";

    const API = "/api/slots";

    function obtenerToken() {
        return localStorage.getItem("token");
    }

    async function solicitar(url, opciones = {}) {
        const token = obtenerToken();

        if (!token) {
            throw new Error(
                "No hay una sesión de Amaeno activa. Inicia sesión nuevamente."
            );
        }

        const respuesta = await fetch(url, {
            ...opciones,
            headers: {
                ...(opciones.headers || {}),
                Authorization: "Bearer " + token
            }
        });

        const resultado = await respuesta.json().catch(() => ({}));

        if (!respuesta.ok) {
            throw new Error(
                resultado.error || "No se pudo acceder a la partida."
            );
        }

        return resultado;
    }

    function obtenerNumeroSlot(nombreArchivo) {
        const coincidencia = /^file(\d+)$/.exec(nombreArchivo);

        return coincidencia ? Number(coincidencia[1]) : null;
    }

    // Mantener los archivos internos de MZ (configuración, globales, etc.)
    // en su almacenamiento original. Solo enviar las partidas al servidor.
    const guardarLocalOriginal = StorageManager.saveObject.bind(StorageManager);
    const cargarLocalOriginal = StorageManager.loadObject.bind(StorageManager);

    StorageManager.saveObject = async function(nombreArchivo, objeto) {
        const numeroSlot = obtenerNumeroSlot(nombreArchivo);

        if (numeroSlot === null) {
            return guardarLocalOriginal(nombreArchivo, objeto);
        }

        const datosRpgMaker = JsonEx.stringify(objeto);
        const savefileInfo = DataManager.makeSavefileInfo();

        const resumen = [
            $dataSystem ? $dataSystem.gameTitle : "EXPOTEC",
            $gameSystem ? $gameSystem.playtimeText() : ""
        ].filter(Boolean).join(" - ");

        await solicitar(API, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                numeroSlot,
                resumen,
                datosRpgMaker,
                savefileInfo
            })
        });
    };

    StorageManager.loadObject = async function(nombreArchivo) {
        const numeroSlot = obtenerNumeroSlot(nombreArchivo);

        if (numeroSlot === null) {
            return cargarLocalOriginal(nombreArchivo);
        }

        const slot = await solicitar(
            API + "/" + numeroSlot,
            { method: "GET" }
        );

        if (typeof slot.datosRpgMaker !== "string") {
            throw new Error("La partida guardada no tiene un formato válido.");
        }

        return JsonEx.parse(slot.datosRpgMaker);
    };

    // La pantalla de carga muestra solo las partidas del usuario conectado.
    DataManager.loadGlobalInfo = async function() {
        if (!obtenerToken()) {
            return [];
        }

        const slots = await solicitar(API, { method: "GET" });
        const globalInfo = [];

        for (const slot of slots) {
            if (slot.savefileInfo) {
                globalInfo[slot.numeroSlot] = slot.savefileInfo;
            }
        }

        return globalInfo;
    };

})();
