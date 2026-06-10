export namespace main {
	
	export class ReportFile {
	    name: string;
	    path: string;
	    date: string;
	    size: string;
	    type: string;
	
	    static createFrom(source: any = {}) {
	        return new ReportFile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.path = source["path"];
	        this.date = source["date"];
	        this.size = source["size"];
	        this.type = source["type"];
	    }
	}
	export class ScanResult {
	    ip: string;
	    hostname: string;
	    port: string;
	    service: string;
	    banner: string;
	    mac: string;
	    vendor: string;
	    os: string;
	
	    static createFrom(source: any = {}) {
	        return new ScanResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.hostname = source["hostname"];
	        this.port = source["port"];
	        this.service = source["service"];
	        this.banner = source["banner"];
	        this.mac = source["mac"];
	        this.vendor = source["vendor"];
	        this.os = source["os"];
	    }
	}
	export class Settings {
	    timeoutMs: number;
	    maxThreads: number;
	    reduceAnim: boolean;
	    highContrast: boolean;
	    uiSize: string;
	    defaultExportPath: string;
	    autoExportFormat: string;
	
	    static createFrom(source: any = {}) {
	        return new Settings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timeoutMs = source["timeoutMs"];
	        this.maxThreads = source["maxThreads"];
	        this.reduceAnim = source["reduceAnim"];
	        this.highContrast = source["highContrast"];
	        this.uiSize = source["uiSize"];
	        this.defaultExportPath = source["defaultExportPath"];
	        this.autoExportFormat = source["autoExportFormat"];
	    }
	}

}

