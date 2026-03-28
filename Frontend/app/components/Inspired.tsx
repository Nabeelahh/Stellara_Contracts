import confidenceIcon from "@/public/images/confidence-icon.svg";
import confidenceImg from "@/public/images/confidence-img.svg";
import marketBeliefIcon from "@/public/images/market-belief-icon.svg";
import marketBeliefImg from "@/public/images/market-belief-img.png";
import learningPathIcon from "@/public/images/learning-path-icon.svg";
import learningPathImg from "@/public/images/learning-path-img.svg";
import Image from "next/image";




function Inspired() {
  return (
       <section className="relative flex flex-col bg-black py-24">
      <div className="mx-auto grid w-full max-w-7xl flex-1 grid-cols-1 items-center gap-8 px-6 mb-8">
                  <h2 className="text-3xl font-light tracking-tight text-white sm:text-4xl lg:text-5xl  max-w-139.75 ">
            <span className="italic text-[#e988f2]">Stay Inspired {" "}</span>  with our latest insights with
            <span className="italic text-[#e988f2]"> Stellara Ai.</span>
          </h2>
            <p className="text-base leading-relaxed text-white sm:text-lg max-w-165.25 lg:text-[1.875rem]">
           Stay ahead with AI-generated market intelligence, educational tips, and real-time Stellar ecosystem updates.
          </p>
        </div>
        <div className="px-6 grid gap-5 md:grid-cols-2 lg:grid-cols-3 max-w-7xl mx-auto">
            <div className="w-full max-w-1104.25 h-141.25 bg-[#1a1a4d] shadow-[0px_4px_80px_10px_#9e8d6b] rounded-[28px] border-4 border-white/20 px-6 py-4">
                <Image src={marketBeliefIcon} alt="Market Belief Icon" className="mb-16" />
                <h3 className="font-normal text-4xl mb-4">AI Market Brief</h3>
                <Image src={marketBeliefImg} alt="Market Belief Image" className="mb-4" />
                <p className="text-2xl lg:text-[1.875rem] leading-tight text-[#e988f2]">Get daily AI-powered summaries of crypto trends, price movements, and key market signals—explained in simple, beginner-friendly language.</p>
            </div>
            <div className="w-full max-w-1104.25 h-141.25 bg-[#d1e7f3] text-black shadow-[0px_4px_80px_10px_#4a1faf] rounded-[28px] border-4 border-[#e988f2]/20 px-6 py-4">
                <Image src={learningPathIcon} alt="Smart Learning Path Icon" className="mb-16" />
                <h3 className="font-normal text-4xl mb-4">Smart Learning Path</h3>
                <Image src={learningPathImg} alt="Smart Learning Path Image" className="mb-4" />
                <p className="text-2xl lg:text-[1.875rem] leading-tight">Master crypto from beginner to pro with AI-guided lessons and instant feedback.</p>
            </div>
            <div className="w-full max-w-1104.25 h-141.25 bg-[#1a1a4d] shadow-[0px_4px_80px_10px_#9e8d6b] rounded-[28px] border-4 border-white/20 px-6 py-4">
                <Image src={confidenceIcon} alt="Trade Confidence Icon" className="mb-16" />
                <h3 className="font-normal text-4xl mb-4">Trade with Confidence</h3>
                <Image src={confidenceImg} alt="Trade Confidence Image" className="mb-4" />
                <p className="text-2xl lg:text-[1.875rem] lg:leading-tight text-[#e988f2]">Turn knowledge into action with secure, seamless Stellar-based trading tools that bridge learning and real-world crypto activity.</p>
            </div>
        </div>
        </section>
  )
}

export default Inspired

 







