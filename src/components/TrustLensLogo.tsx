import React, { useState } from 'react';

const REAL_LOGO_URL = 'https://i.postimg.cc/sXwntWVn/2a-Obo-R1a-Ady-R4p-MWLfu-Cr-D8AB9LHFOPAN7JSzj-N2.jpg';
const LOCAL_LOGO_FALLBACK = '/logo.png';

interface LogoProps {
  className?: string;
  showText?: boolean;
  size?: 'sm' | 'md' | 'lg';
  iconOnly?: boolean;
}

export const TrustLensLogo: React.FC<LogoProps> = ({ 
  className = '', 
  showText = true, 
  size = 'md',
  iconOnly = false
}) => {
  const [imgSrc, setImgSrc] = useState(REAL_LOGO_URL);
  const dim = size === 'sm' ? 'w-8 h-8' : size === 'lg' ? 'w-16 h-16' : 'w-10 h-10';
  const shouldShowText = showText && !iconOnly;

  return (
    <div className={`flex items-center gap-2.5 ${className}`}>
      <img 
        src={imgSrc} 
        alt="TrustLens AI Cyber Shield & Lens Logo" 
        referrerPolicy="no-referrer"
        crossOrigin="anonymous"
        onError={() => {
          if (imgSrc !== LOCAL_LOGO_FALLBACK) {
            setImgSrc(LOCAL_LOGO_FALLBACK);
          }
        }}
        className={`${dim} object-contain drop-shadow-[0_0_20px_rgba(56,189,248,0.6)] rounded-xl`}
      />
      {shouldShowText && (
        <div className="flex items-center gap-1.5">
          <span className="font-extrabold text-white tracking-tight text-base sm:text-lg">
            TrustLens<span className="bg-gradient-to-r from-sky-400 to-cyan-300 bg-clip-text text-transparent">.AI</span>
          </span>
          <span className="text-[10px] font-mono font-bold text-sky-400/90 bg-sky-950/70 border border-sky-800/60 px-1.5 py-0.5 rounded-full">
            v2.0
          </span>
        </div>
      )}
    </div>
  );
};
